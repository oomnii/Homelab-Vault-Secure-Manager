from __future__ import annotations

import re

from app.extensions import db
from app.models import Folder, LoginHistory, SecureID, SecureNote, User, VaultItem
from app.security import decrypt_value


def setup_master_user(client):
    response = client.post(
        '/setup',
        data={
            'username': 'admin',
            'email': 'admin@example.com',
            'password': 'supersecure123',
            'confirm_password': 'supersecure123',
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b'Master account created' in response.data



def login_with_otp(client):
    response = client.post(
        '/login',
        data={'identifier': 'admin', 'password': 'supersecure123'},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b'Verify Email OTP' in response.data
    match = re.search(br'<span id="dev-otp-value">(\d{6})</span>', response.data)
    assert match, response.data.decode('utf-8')
    otp = match.group(1).decode('utf-8')

    response = client.post('/verify-otp', data={'otp': otp}, follow_redirects=True)
    assert response.status_code == 200
    assert b'Dashboard' in response.data



def test_master_account_deletion_flow(client, app_instance):
    setup_master_user(client)
    login_with_otp(client)

    page = client.get('/account')
    assert page.status_code == 200
    assert b'Danger Zone' in page.data

    bad = client.post(
        '/account',
        data={'action': 'request_account_deletion', 'master_password': 'wrong-password'},
        follow_redirects=True,
    )
    assert bad.status_code == 200
    assert b'not correct' in bad.data.lower()

    step = client.post(
        '/account',
        data={'action': 'request_account_deletion', 'master_password': 'supersecure123'},
        follow_redirects=True,
    )
    assert step.status_code == 200
    assert b'deletion-dev-otp-value' in step.data

    match = re.search(br'<span id="deletion-dev-otp-value">(\d{6})</span>', step.data)
    assert match
    otp = match.group(1).decode('utf-8')

    done = client.post(
        '/account',
        data={'action': 'confirm_account_deletion', 'otp': otp},
        follow_redirects=True,
    )
    assert done.status_code == 200
    assert b'Create Master Account' in done.data

    with app_instance.app_context():
        assert User.query.count() == 0
        assert Folder.query.count() == 0
        assert VaultItem.query.count() == 0


def test_first_run_redirects_to_setup(client):
    response = client.get('/', follow_redirects=True)
    assert response.status_code == 200
    assert b'Create Master Account' in response.data



def test_setup_creates_user_with_email_and_hashes_password(client, app_instance):
    setup_master_user(client)
    with app_instance.app_context():
        user = User.query.filter_by(username='admin').first()
        assert user is not None
        assert user.email == 'admin@example.com'
        assert user.password_hash != 'supersecure123'
        assert 'supersecure123' not in user.password_hash



def test_login_logout_and_auth_guard(client, app_instance):
    setup_master_user(client)
    protected = client.get('/dashboard', follow_redirects=True)
    assert b'Sign in to Homelab Vault' in protected.data

    login_with_otp(client)
    response = client.post('/logout', follow_redirects=True)
    assert b'logged out' in response.data.lower()

    with app_instance.app_context():
        assert LoginHistory.query.count() >= 4



def test_folder_password_secure_id_secure_note_and_backup_crud(client, app_instance):
    setup_master_user(client)
    login_with_otp(client)

    create_folder_response = client.post(
        '/folders/create',
        data={'name': 'Banking'},
        follow_redirects=True,
    )
    assert b'Folder created' in create_folder_response.data

    with app_instance.app_context():
        folder = Folder.query.filter_by(name='Banking').first()
        assert folder is not None
        assert folder.icon == '📂'
        folder_id = folder.id

    create_vault_response = client.post(
        '/vault/create',
        data={
            'title': 'SBI Netbanking',
            'website': 'https://sbi.co.in',
            'username': 'om@example.com',
            'password': 'BankPass@123',
            'notes': 'Primary account',
            'folder_id': str(folder_id),
        },
        follow_redirects=True,
    )
    assert b'Vault item added' in create_vault_response.data
    assert b'SBI Netbanking' in create_vault_response.data

    with app_instance.app_context():
        item = VaultItem.query.filter_by(title='SBI Netbanking').first()
        assert item is not None
        assert item.password_encrypted != 'BankPass@123'
        assert decrypt_value(item.password_encrypted) == 'BankPass@123'
        item_id = item.id

    create_secure_id_response = client.post(
        '/secure-ids/create',
        data={
            'title': 'My Aadhaar',
            'id_type': 'Aadhaar',
            'id_value': '1234-5678-9012',
            'expiry_date': '',
            'notes': 'Government ID',
            'folder_id': str(folder_id),
        },
        follow_redirects=True,
    )
    assert b'Secure ID added' in create_secure_id_response.data
    assert b'My Aadhaar' in create_secure_id_response.data

    create_secure_note_response = client.post(
        '/secure-notes/create',
        data={
            'title': 'Locker PIN Hint',
            'note_content': 'Bank locker alternate key is in steel drawer.',
            'folder_id': str(folder_id),
        },
        follow_redirects=True,
    )
    assert b'Secure note added' in create_secure_note_response.data
    assert b'Locker PIN Hint' in create_secure_note_response.data

    with app_instance.app_context():
        secure_id = SecureID.query.filter_by(title='My Aadhaar').first()
        assert secure_id is not None
        assert secure_id.id_value_encrypted != '1234-5678-9012'
        assert decrypt_value(secure_id.id_value_encrypted) == '1234-5678-9012'
        secure_id_id = secure_id.id

        secure_note = SecureNote.query.filter_by(title='Locker PIN Hint').first()
        assert secure_note is not None
        assert 'steel drawer' in decrypt_value(secure_note.note_encrypted)
        secure_note_id = secure_note.id

    update_vault_response = client.post(
        f'/vault/{item_id}/update',
        data={
            'title': 'SBI Online Banking',
            'website': 'https://online.sbi.co.in',
            'username': 'om@example.com',
            'password': 'UpdatedPass@123',
            'notes': 'Updated note',
            'folder_id': str(folder_id),
        },
        follow_redirects=True,
    )
    assert b'Vault item updated' in update_vault_response.data
    assert b'SBI Online Banking' in update_vault_response.data

    update_secure_id_response = client.post(
        f'/secure-ids/{secure_id_id}/update',
        data={
            'title': 'My Updated Aadhaar',
            'id_type': 'Aadhaar',
            'id_value': '9999-8888-7777',
            'expiry_date': '',
            'notes': 'Updated Government ID',
            'folder_id': str(folder_id),
        },
        follow_redirects=True,
    )
    assert b'Secure ID updated' in update_secure_id_response.data

    update_secure_note_response = client.post(
        f'/secure-notes/{secure_note_id}/update',
        data={
            'title': 'Locker PIN Hint Updated',
            'note_content': 'Updated secure note body.',
            'folder_id': str(folder_id),
        },
        follow_redirects=True,
    )
    assert b'Secure note updated' in update_secure_note_response.data

    folder_detail_response = client.get(f'/folders/{folder_id}')
    assert folder_detail_response.status_code == 200
    assert b'SBI Online Banking' in folder_detail_response.data
    assert b'My Updated Aadhaar' in folder_detail_response.data
    assert b'Locker PIN Hint Updated' in folder_detail_response.data

    folders_list = client.get('/folders')
    assert folders_list.status_code == 200
    assert f'/folders/{folder_id}'.encode() in folders_list.data

    history_response = client.get('/history', follow_redirects=True)
    assert b'Login History' in history_response.data
    assert b'IST' in history_response.data

    backup_response = client.post('/backup/export', follow_redirects=False)
    assert backup_response.status_code == 200
    assert backup_response.headers['Content-Type'].startswith('application/json')
    assert b'encrypted-vault-export' in backup_response.data
    assert b'password_encrypted' in backup_response.data
    assert b'note_encrypted' in backup_response.data

    delete_secure_note_response = client.post(
        f'/secure-notes/{secure_note_id}/delete',
        follow_redirects=True,
    )
    assert b'Secure note deleted' in delete_secure_note_response.data

    delete_secure_id_response = client.post(
        f'/secure-ids/{secure_id_id}/delete',
        follow_redirects=True,
    )
    assert b'Secure ID deleted' in delete_secure_id_response.data

    delete_vault_response = client.post(
        f'/vault/{item_id}/delete',
        follow_redirects=True,
    )
    assert b'Vault item deleted' in delete_vault_response.data

    delete_folder_response = client.post(
        f'/folders/{folder_id}/delete',
        follow_redirects=True,
    )
    assert b'Folder deleted' in delete_folder_response.data

    assert client.get(f'/folders/{folder_id}').status_code == 404

    with app_instance.app_context():
        assert Folder.query.count() == 0
        assert VaultItem.query.count() == 0
        assert SecureID.query.count() == 0
        assert SecureNote.query.count() == 0
        assert db.session.query(User).count() == 1



def test_folder_detail_not_found_requires_login_and_404(client, app_instance):
    assert client.get('/folders/1').status_code == 302
    setup_master_user(client)
    login_with_otp(client)
    assert client.get('/folders/99999').status_code == 404


def test_validation_messages_and_invalid_folder_handling(client, app_instance):
    setup_master_user(client)
    login_with_otp(client)

    response = client.post('/vault/create', data={'title': '', 'password': ''}, follow_redirects=True)
    assert b'Title and password are required' in response.data

    response = client.post('/secure-ids/create', data={'title': '', 'id_value': ''}, follow_redirects=True)
    assert b'Title and ID value are required' in response.data

    response = client.post('/secure-notes/create', data={'title': '', 'note_content': ''}, follow_redirects=True)
    assert b'Title and secure note content are required' in response.data

    response = client.post('/folders/create', data={'name': 'Personal'}, follow_redirects=True)
    assert b'Folder created' in response.data
    response = client.post('/folders/create', data={'name': 'personal'}, follow_redirects=True)
    assert b'already exists' in response.data

    response = client.post(
        '/vault/create',
        data={'title': 'Loose Entry', 'password': 'abc12345', 'folder_id': '9999'},
        follow_redirects=True,
    )
    assert b'Vault item added' in response.data

    response = client.post(
        '/secure-ids/create',
        data={'title': 'PAN', 'id_value': 'AAAAA1111A', 'folder_id': '9999'},
        follow_redirects=True,
    )
    assert b'Secure ID added' in response.data

    response = client.post(
        '/secure-notes/create',
        data={'title': 'Secret Pin', 'note_content': '1234', 'folder_id': '9999'},
        follow_redirects=True,
    )
    assert b'Secure note added' in response.data

    with app_instance.app_context():
        loose_item = VaultItem.query.filter_by(title='Loose Entry').first()
        loose_id = SecureID.query.filter_by(title='PAN').first()
        loose_note = SecureNote.query.filter_by(title='Secret Pin').first()
        assert loose_item is not None and loose_item.folder_id is None
        assert loose_id is not None and loose_id.folder_id is None
        assert loose_note is not None and loose_note.folder_id is None
