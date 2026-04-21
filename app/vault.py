from __future__ import annotations

import json
from datetime import UTC, datetime

from flask import Blueprint, Response, abort, current_app, flash, redirect, render_template, request, session, url_for
from sqlalchemy import or_
from werkzeug.security import check_password_hash

from .audit import record_login_event
from .extensions import db
from .mailer import send_account_deletion_otp
from .models import Folder, LoginHistory, SecureID, SecureNote, User, VaultItem
from .security import create_otp_for_user, decrypt_value, encrypt_value, format_datetime_ist, login_required, verify_user_otp

vault_bp = Blueprint('vault', __name__)

SESSION_ACCOUNT_DELETION_OTP_PENDING = 'account_deletion_otp_pending'


def _folder_id_or_none(raw_folder_id: str | None):
    if not raw_folder_id:
        return None
    try:
        folder_id = int(raw_folder_id)
    except ValueError:
        return None
    return folder_id if db.session.get(Folder, folder_id) is not None else None


def _get_or_404(model, object_id: int):
    instance = db.session.get(model, object_id)
    if instance is None:
        abort(404)
    return instance


def _folder_name_exists(name: str, exclude_id: int | None = None) -> bool:
    query = Folder.query.filter(db.func.lower(Folder.name) == name.lower())
    if exclude_id is not None:
        query = query.filter(Folder.id != exclude_id)
    return db.session.query(query.exists()).scalar()


def _utc_iso(value) -> str | None:
    return value.isoformat() + 'Z' if value else None


@vault_bp.get('/dashboard')
@login_required
def dashboard():
    recent_items = VaultItem.query.order_by(VaultItem.updated_at.desc()).limit(5).all()
    recent_secure_ids = SecureID.query.order_by(SecureID.updated_at.desc()).limit(5).all()
    recent_secure_notes = SecureNote.query.order_by(SecureNote.updated_at.desc()).limit(5).all()
    recent_history = LoginHistory.query.order_by(LoginHistory.occurred_at.desc()).limit(8).all()
    last_successful_login = (
        LoginHistory.query.filter_by(event_type='otp_verification', status='passed')
        .order_by(LoginHistory.occurred_at.desc())
        .first()
    )

    stats = {
        'passwords': VaultItem.query.count(),
        'folders': Folder.query.count(),
        'secure_ids': SecureID.query.count(),
        'secure_notes': SecureNote.query.count(),
        'login_events': LoginHistory.query.count(),
    }
    return render_template(
        'dashboard.html',
        recent_items=recent_items,
        recent_secure_ids=recent_secure_ids,
        recent_secure_notes=recent_secure_notes,
        recent_history=recent_history,
        last_successful_login=last_successful_login,
        stats=stats,
        decrypt_value=decrypt_value,
    )


@vault_bp.get('/folders')
@login_required
def folders():
    all_folders = Folder.query.order_by(Folder.name.asc()).all()
    return render_template('folders.html', folders=all_folders)


@vault_bp.get('/folders/<int:folder_id>')
@login_required
def folder_detail(folder_id: int):
    folder = _get_or_404(Folder, folder_id)
    vault_items = VaultItem.query.filter_by(folder_id=folder_id).order_by(VaultItem.updated_at.desc()).all()
    secure_ids_items = SecureID.query.filter_by(folder_id=folder_id).order_by(SecureID.updated_at.desc()).all()
    secure_notes_items = SecureNote.query.filter_by(folder_id=folder_id).order_by(SecureNote.updated_at.desc()).all()
    return render_template(
        'folder_detail.html',
        folder=folder,
        vault_items=vault_items,
        secure_ids_items=secure_ids_items,
        secure_notes_items=secure_notes_items,
        decrypt_value=decrypt_value,
    )


@vault_bp.post('/folders/create')
@login_required
def create_folder():
    name = request.form.get('name', '').strip()

    if not name:
        flash('Folder name is required.', 'danger')
    elif _folder_name_exists(name):
        flash('A folder with that name already exists.', 'warning')
    else:
        folder = Folder(name=name, icon='📂')
        db.session.add(folder)
        db.session.commit()
        flash('Folder created.', 'success')

    return redirect(url_for('vault.folders'))


def _purge_master_account_and_vault() -> None:
    """Remove all vault data and the sole master user (single-user deployment)."""
    VaultItem.query.delete()
    SecureID.query.delete()
    SecureNote.query.delete()
    Folder.query.delete()
    LoginHistory.query.delete()
    User.query.delete()
    db.session.commit()


@vault_bp.route('/account', methods=['GET', 'POST'])
@login_required
def account_page():
    user = db.session.get(User, session.get('user_id'))
    if user is None:
        session.clear()
        flash('Please log in to continue.', 'warning')
        return redirect(url_for('auth.login'))

    deletion_otp_pending = bool(session.get(SESSION_ACCOUNT_DELETION_OTP_PENDING))
    deletion_dev_otp = session.get('deletion_dev_otp')

    if request.method == 'POST':
        action = request.form.get('action', '').strip()

        if action == 'cancel_account_deletion':
            session.pop(SESSION_ACCOUNT_DELETION_OTP_PENDING, None)
            session.pop('deletion_dev_otp', None)
            user.otp_code_hash = None
            user.otp_expires_at = None
            user.otp_attempts = 0
            db.session.commit()
            flash('Account deletion cancelled.', 'info')
            return redirect(url_for('vault.account_page'))

        if action == 'request_account_deletion':
            password = request.form.get('master_password', '')
            if not check_password_hash(user.password_hash, password):
                record_login_event(
                    event_type='account_deletion',
                    status='failed',
                    username_snapshot=user.username,
                    user=user,
                    detail='Invalid master password for deletion request.',
                )
                flash('That master password is not correct.', 'danger')
                return redirect(url_for('vault.account_page'))

            if not user.email:
                flash('A verified email is required. You cannot complete deletion without OTP delivery.', 'danger')
                return redirect(url_for('vault.account_page'))

            otp_code = create_otp_for_user(user)
            db.session.commit()

            if current_app.config.get('OTP_DEV_MODE') and not current_app.testing:
                current_app.logger.warning(
                    '[OTP_DEV_MODE / local only] Account deletion OTP for %r: %s',
                    user.username,
                    otp_code,
                )

            sent, message = send_account_deletion_otp(user.email, user.username, otp_code)

            if current_app.config.get('OTP_DEV_MODE') or current_app.testing:
                session['deletion_dev_otp'] = otp_code
            else:
                session.pop('deletion_dev_otp', None)

            record_login_event(
                event_type='account_deletion',
                status='sent' if sent else 'failed',
                username_snapshot=user.username,
                user=user,
                detail=message,
            )

            if not sent and not (current_app.config.get('OTP_DEV_MODE') or current_app.testing):
                user.otp_code_hash = None
                user.otp_expires_at = None
                user.otp_attempts = 0
                db.session.commit()
                flash(message, 'danger')
                return redirect(url_for('vault.account_page'))

            session[SESSION_ACCOUNT_DELETION_OTP_PENDING] = True
            flash(
                f'{message} Enter the code below to permanently delete this master account and all vault data.',
                'success' if sent else 'warning',
            )
            return redirect(url_for('vault.account_page'))

        if action == 'resend_account_deletion_otp':
            if not session.get(SESSION_ACCOUNT_DELETION_OTP_PENDING):
                flash('Start the deletion flow again with your master password.', 'warning')
                return redirect(url_for('vault.account_page'))

            otp_code = create_otp_for_user(user)
            db.session.commit()

            if current_app.config.get('OTP_DEV_MODE') and not current_app.testing:
                current_app.logger.warning(
                    '[OTP_DEV_MODE / local only] Account deletion OTP (resend) for %r: %s',
                    user.username,
                    otp_code,
                )

            sent, message = send_account_deletion_otp(user.email, user.username, otp_code)
            if current_app.config.get('OTP_DEV_MODE') or current_app.testing:
                session['deletion_dev_otp'] = otp_code
            record_login_event(
                event_type='account_deletion',
                status='sent' if sent else 'failed',
                username_snapshot=user.username,
                user=user,
                detail=f'Resend: {message}',
            )

            if not sent and not (current_app.config.get('OTP_DEV_MODE') or current_app.testing):
                user.otp_code_hash = None
                user.otp_expires_at = None
                user.otp_attempts = 0
                db.session.commit()
                session.pop(SESSION_ACCOUNT_DELETION_OTP_PENDING, None)
                flash(message, 'danger')
                return redirect(url_for('vault.account_page'))

            flash(message, 'success' if sent else 'warning')
            return redirect(url_for('vault.account_page'))

        if action == 'confirm_account_deletion':
            if not session.get(SESSION_ACCOUNT_DELETION_OTP_PENDING):
                flash('Confirm your master password first to receive a deletion code.', 'warning')
                return redirect(url_for('vault.account_page'))

            otp = request.form.get('otp', '').strip()
            valid, message = verify_user_otp(user, otp)
            db.session.commit()

            if not valid:
                record_login_event(
                    event_type='account_deletion',
                    status='failed',
                    username_snapshot=user.username,
                    user=user,
                    detail=message,
                )
                if 'expired' in message.lower() or 'too many' in message.lower() or 'log in again' in message.lower():
                    session.pop(SESSION_ACCOUNT_DELETION_OTP_PENDING, None)
                    session.pop('deletion_dev_otp', None)
                    user.otp_code_hash = None
                    user.otp_expires_at = None
                    user.otp_attempts = 0
                    db.session.commit()
                flash(message, 'danger')
                return redirect(url_for('vault.account_page'))

            record_login_event(
                event_type='account_deletion',
                status='completed',
                username_snapshot=user.username,
                user=user,
                detail='Master account and all vault data removed after OTP confirmation.',
            )
            _purge_master_account_and_vault()
            session.clear()
            flash('Your master account and all related data have been permanently deleted.', 'success')
            return redirect(url_for('auth.setup'))

        flash('Unknown action.', 'warning')
        return redirect(url_for('vault.account_page'))

    return render_template(
        'account.html',
        user=user,
        deletion_otp_pending=deletion_otp_pending,
        deletion_dev_otp=deletion_dev_otp,
    )


@vault_bp.post('/folders/<int:folder_id>/delete')
@login_required
def delete_folder(folder_id: int):
    folder = _get_or_404(Folder, folder_id)
    for item in folder.vault_items:
        item.folder_id = None
    for secure_id in folder.secure_ids:
        secure_id.folder_id = None
    for secure_note in folder.secure_notes:
        secure_note.folder_id = None
    db.session.delete(folder)
    db.session.commit()
    flash('Folder deleted. Linked items were kept.', 'info')
    return redirect(url_for('vault.folders'))


@vault_bp.get('/vault')
@login_required
def vault_items():
    search = request.args.get('search', '').strip()
    folder_id = request.args.get('folder_id', '').strip()

    query = VaultItem.query
    if search:
        like = f'%{search}%'
        query = query.filter(
            or_(
                VaultItem.title.ilike(like),
                VaultItem.username.ilike(like),
                VaultItem.website.ilike(like),
                VaultItem.notes.ilike(like),
            )
        )
    if folder_id.isdigit() and db.session.get(Folder, int(folder_id)) is not None:
        query = query.filter_by(folder_id=int(folder_id))

    items = query.order_by(VaultItem.updated_at.desc()).all()
    folders = Folder.query.order_by(Folder.name.asc()).all()
    return render_template(
        'vault.html',
        items=items,
        folders=folders,
        decrypt_value=decrypt_value,
        selected_folder_id=folder_id,
        search=search,
    )


@vault_bp.post('/vault/create')
@login_required
def create_vault_item():
    title = request.form.get('title', '').strip()
    website = request.form.get('website', '').strip()
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    notes = request.form.get('notes', '').strip()
    folder_id = _folder_id_or_none(request.form.get('folder_id'))

    if not title or not password:
        flash('Title and password are required.', 'danger')
        return redirect(url_for('vault.vault_items'))

    item = VaultItem(
        title=title,
        website=website,
        username=username,
        password_encrypted=encrypt_value(password),
        notes=notes,
        folder_id=folder_id,
    )
    db.session.add(item)
    db.session.commit()
    flash('Vault item added.', 'success')
    return redirect(url_for('vault.vault_items'))


@vault_bp.post('/vault/<int:item_id>/update')
@login_required
def update_vault_item(item_id: int):
    item = _get_or_404(VaultItem, item_id)
    title = request.form.get('title', '').strip()
    password = request.form.get('password', '').strip()

    if not title or not password:
        flash('Title and password are required.', 'danger')
        return redirect(url_for('vault.vault_items'))

    item.title = title
    item.website = request.form.get('website', '').strip()
    item.username = request.form.get('username', '').strip()
    item.password_encrypted = encrypt_value(password)
    item.notes = request.form.get('notes', '').strip()
    item.folder_id = _folder_id_or_none(request.form.get('folder_id'))
    db.session.commit()
    flash('Vault item updated.', 'success')
    return redirect(url_for('vault.vault_items'))


@vault_bp.post('/vault/<int:item_id>/delete')
@login_required
def delete_vault_item(item_id: int):
    item = _get_or_404(VaultItem, item_id)
    db.session.delete(item)
    db.session.commit()
    flash('Vault item deleted.', 'info')
    return redirect(url_for('vault.vault_items'))


@vault_bp.get('/secure-ids')
@login_required
def secure_ids():
    search = request.args.get('search', '').strip()
    folder_id = request.args.get('folder_id', '').strip()

    query = SecureID.query
    if search:
        like = f'%{search}%'
        query = query.filter(
            or_(
                SecureID.title.ilike(like),
                SecureID.id_type.ilike(like),
                SecureID.notes.ilike(like),
                SecureID.expiry_date.ilike(like),
            )
        )
    if folder_id.isdigit() and db.session.get(Folder, int(folder_id)) is not None:
        query = query.filter_by(folder_id=int(folder_id))

    items = query.order_by(SecureID.updated_at.desc()).all()
    folders = Folder.query.order_by(Folder.name.asc()).all()
    return render_template(
        'secure_ids.html',
        items=items,
        folders=folders,
        decrypt_value=decrypt_value,
        selected_folder_id=folder_id,
        search=search,
    )


@vault_bp.post('/secure-ids/create')
@login_required
def create_secure_id():
    title = request.form.get('title', '').strip()
    id_type = request.form.get('id_type', '').strip() or 'General ID'
    id_value = request.form.get('id_value', '').strip()
    expiry_date = request.form.get('expiry_date', '').strip()
    notes = request.form.get('notes', '').strip()
    folder_id = _folder_id_or_none(request.form.get('folder_id'))

    if not title or not id_value:
        flash('Title and ID value are required.', 'danger')
        return redirect(url_for('vault.secure_ids'))

    item = SecureID(
        title=title,
        id_type=id_type,
        id_value_encrypted=encrypt_value(id_value),
        expiry_date=expiry_date,
        notes=notes,
        folder_id=folder_id,
    )
    db.session.add(item)
    db.session.commit()
    flash('Secure ID added.', 'success')
    return redirect(url_for('vault.secure_ids'))


@vault_bp.post('/secure-ids/<int:item_id>/update')
@login_required
def update_secure_id(item_id: int):
    item = _get_or_404(SecureID, item_id)
    title = request.form.get('title', '').strip()
    id_value = request.form.get('id_value', '').strip()

    if not title or not id_value:
        flash('Title and ID value are required.', 'danger')
        return redirect(url_for('vault.secure_ids'))

    item.title = title
    item.id_type = request.form.get('id_type', '').strip() or 'General ID'
    item.id_value_encrypted = encrypt_value(id_value)
    item.expiry_date = request.form.get('expiry_date', '').strip()
    item.notes = request.form.get('notes', '').strip()
    item.folder_id = _folder_id_or_none(request.form.get('folder_id'))
    db.session.commit()
    flash('Secure ID updated.', 'success')
    return redirect(url_for('vault.secure_ids'))


@vault_bp.post('/secure-ids/<int:item_id>/delete')
@login_required
def delete_secure_id(item_id: int):
    item = _get_or_404(SecureID, item_id)
    db.session.delete(item)
    db.session.commit()
    flash('Secure ID deleted.', 'info')
    return redirect(url_for('vault.secure_ids'))


@vault_bp.get('/secure-notes')
@login_required
def secure_notes():
    search = request.args.get('search', '').strip()
    folder_id = request.args.get('folder_id', '').strip()

    query = SecureNote.query
    if search:
        like = f'%{search}%'
        query = query.filter(SecureNote.title.ilike(like))
    if folder_id.isdigit() and db.session.get(Folder, int(folder_id)) is not None:
        query = query.filter_by(folder_id=int(folder_id))

    items = query.order_by(SecureNote.updated_at.desc()).all()
    folders = Folder.query.order_by(Folder.name.asc()).all()
    return render_template(
        'secure_notes.html',
        items=items,
        folders=folders,
        decrypt_value=decrypt_value,
        selected_folder_id=folder_id,
        search=search,
    )


@vault_bp.post('/secure-notes/create')
@login_required
def create_secure_note():
    title = request.form.get('title', '').strip()
    note_content = request.form.get('note_content', '').strip()
    folder_id = _folder_id_or_none(request.form.get('folder_id'))

    if not title or not note_content:
        flash('Title and secure note content are required.', 'danger')
        return redirect(url_for('vault.secure_notes'))

    item = SecureNote(
        title=title,
        note_encrypted=encrypt_value(note_content),
        folder_id=folder_id,
    )
    db.session.add(item)
    db.session.commit()
    flash('Secure note added.', 'success')
    return redirect(url_for('vault.secure_notes'))


@vault_bp.post('/secure-notes/<int:item_id>/update')
@login_required
def update_secure_note(item_id: int):
    item = _get_or_404(SecureNote, item_id)
    title = request.form.get('title', '').strip()
    note_content = request.form.get('note_content', '').strip()

    if not title or not note_content:
        flash('Title and secure note content are required.', 'danger')
        return redirect(url_for('vault.secure_notes'))

    item.title = title
    item.note_encrypted = encrypt_value(note_content)
    item.folder_id = _folder_id_or_none(request.form.get('folder_id'))
    db.session.commit()
    flash('Secure note updated.', 'success')
    return redirect(url_for('vault.secure_notes'))


@vault_bp.post('/secure-notes/<int:item_id>/delete')
@login_required
def delete_secure_note(item_id: int):
    item = _get_or_404(SecureNote, item_id)
    db.session.delete(item)
    db.session.commit()
    flash('Secure note deleted.', 'info')
    return redirect(url_for('vault.secure_notes'))


@vault_bp.get('/backup')
@login_required
def backup_page():
    stats = {
        'passwords': VaultItem.query.count(),
        'secure_ids': SecureID.query.count(),
        'secure_notes': SecureNote.query.count(),
        'folders': Folder.query.count(),
    }
    return render_template('backup.html', stats=stats)


@vault_bp.post('/backup/export')
@login_required
def export_backup():
    current_user = db.session.get(User, session.get('user_id'))
    folders = Folder.query.order_by(Folder.name.asc()).all()
    vault_items = VaultItem.query.order_by(VaultItem.title.asc()).all()
    secure_ids_items = SecureID.query.order_by(SecureID.title.asc()).all()
    secure_notes_items = SecureNote.query.order_by(SecureNote.title.asc()).all()

    payload = {
        'app_name': 'Homelab Password Manager',
        'export_type': 'encrypted-vault-export',
        'exported_by': current_user.username if current_user else session.get('username', 'Unknown'),
        'exported_at_utc': None,
        'exported_at_ist': None,
        'notes': [
            'Encrypted fields stay encrypted in this export.',
            'This file is intended for backup and migration, not direct human reading.',
            'Keep the same SECRET_KEY or FERNET_KEY to decrypt exported ciphertext later.',
        ],
        'folders': [
            {
                'id': folder.id,
                'name': folder.name,
                'icon': '📂',
                'created_at_utc': _utc_iso(folder.created_at),
            }
            for folder in folders
        ],
        'vault_items': [
            {
                'title': item.title,
                'website': item.website,
                'username': item.username,
                'password_encrypted': item.password_encrypted,
                'notes': item.notes,
                'folder_id': item.folder_id,
                'created_at_utc': _utc_iso(item.created_at),
                'updated_at_utc': _utc_iso(item.updated_at),
            }
            for item in vault_items
        ],
        'secure_ids': [
            {
                'title': item.title,
                'id_type': item.id_type,
                'id_value_encrypted': item.id_value_encrypted,
                'expiry_date': item.expiry_date,
                'notes': item.notes,
                'folder_id': item.folder_id,
                'created_at_utc': _utc_iso(item.created_at),
                'updated_at_utc': _utc_iso(item.updated_at),
            }
            for item in secure_ids_items
        ],
        'secure_notes': [
            {
                'title': item.title,
                'note_encrypted': item.note_encrypted,
                'folder_id': item.folder_id,
                'created_at_utc': _utc_iso(item.created_at),
                'updated_at_utc': _utc_iso(item.updated_at),
            }
            for item in secure_notes_items
        ],
    }

    exported_at = datetime.now(UTC).replace(microsecond=0)
    payload['exported_at_utc'] = exported_at.isoformat().replace('+00:00', 'Z')
    payload['exported_at_ist'] = format_datetime_ist(exported_at.replace(tzinfo=None))

    filename = f"homelab-vault-backup-{exported_at.strftime('%Y%m%d-%H%M%S')}.json"
    json_bytes = json.dumps(payload, indent=2).encode('utf-8')
    return Response(
        json_bytes,
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment; filename={filename}'},
    )


@vault_bp.get('/history')
@login_required
def history_page():
    history_items = LoginHistory.query.order_by(LoginHistory.occurred_at.desc()).limit(200).all()
    return render_template('history.html', history_items=history_items)
