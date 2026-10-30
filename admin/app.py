import json
import os
import sys
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

import auth_manager
import api_client
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from trusted_keys import (
    TRUST_STORE,
    fingerprint,
    load_trusted_keys,
    provision_trusted_key,
)

st.set_page_config(page_title="Secure Storage Admin", page_icon="🛡️", layout="wide")
st.title("🛡️ Secure Storage — Admin Console")
st.caption(
    "Approve clients, manage trusted sender keys, control access, and review audit events."
)


def validate_sender_signing_key(pem_bytes: bytes) -> str:
    """Validate a PEM EC signing public key and return its SHA-256 fingerprint."""
    try:
        public_key = serialization.load_pem_public_key(pem_bytes)
    except (ValueError, TypeError) as exc:
        raise ValueError("The uploaded file is not a valid PEM public key.") from exc

    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("The sender signing key must be an elliptic-curve public key.")

    if public_key.curve.name != "secp256k1":
        raise ValueError(
            f"Expected a SECP256K1 signing key; received {public_key.curve.name}."
        )

    # Keep the exact PEM representation consistent with the package fingerprint.
    return fingerprint(pem_bytes)


def remove_trusted_key(username: str) -> bool:
    """Remove one sender from the local trust store using an atomic file update."""
    path = Path(TRUST_STORE)
    entries = load_trusted_keys(path)
    if username not in entries:
        return False

    del entries[username]
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    temp_path.write_text(
        json.dumps(entries, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    try:
        os.chmod(temp_path, 0o600)
    except OSError:
        pass
    temp_path.replace(path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return True


if "admin_user" not in st.session_state:
    st.session_state.admin_user = None
if "admin_api_token" not in st.session_state:
    st.session_state.admin_api_token = None

if not st.session_state.admin_user:
    with st.form("admin_login"):
        username_input = st.text_input("Administrator username")
        password_input = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Sign in")

    if submitted:
        try:
            result = api_client.login(username_input, password_input)
            user = result["user"]
            if user["role"] == "admin":
                st.session_state.admin_user = user["username"]
                st.session_state.admin_api_token = result["access_token"]
                st.rerun()
            st.error("This account is not an administrator.")
        except Exception as exc:
            st.error(str(exc))

    st.info(
        "Use the existing administrator account. The first admin is created from a terminal only when no admin exists."
    )
    st.stop()

if st.button("Sign out"):
    try:
        api_client.log_event(st.session_state.admin_api_token, "logout", "admin console")
    except Exception:
        pass
    st.session_state.admin_user = None
    st.session_state.admin_api_token = None
    st.rerun()

admin_username = st.session_state.admin_user
st.success(f"Signed in as administrator: {admin_username}")

try:
    users = api_client.admin_peers(st.session_state.admin_api_token)
except Exception as exc:
    st.error(f"Could not load accounts from central API: {exc}")
    st.stop()
pending_users = [user for user in users if user["status"] == "pending"]
approved_senders = [
    user for user in users if user["role"] == "sender" and user["status"] == "approved"
]

st.subheader(f"Pending registrations ({len(pending_users)})")
if not pending_users:
    st.write("No pending registrations.")

for user in pending_users:
    with st.container(border=True):
        col1, col2, col3 = st.columns([3, 2, 3])
        col1.markdown(f"**{user['username']}**")
        col1.caption(f"Role: {user['role']} · Registered: {user['created_at']}")
        if col2.button("Approve", key=f"approve_{user['username']}", type="primary"):
            api_client.review_peer(st.session_state.admin_api_token, user["username"], "approved")
            st.rerun()
        if col3.button("Reject", key=f"reject_{user['username']}"):
            api_client.review_peer(st.session_state.admin_api_token, user["username"], "rejected")
            st.rerun()

st.divider()
st.header("Trusted sender signing keys")
st.write(
    "Only approved sender accounts can be registered here. Verify the sender's "
    "public-key fingerprint through an independent trusted channel before adding "
    "or replacing a key. Never upload or expose a private key."
)
st.caption(f"Local trust-store location: {TRUST_STORE}")

try:
    trusted_entries = load_trusted_keys(Path(TRUST_STORE))
except (OSError, ValueError, json.JSONDecodeError) as exc:
    trusted_entries = {}
    st.error(f"Could not read the trusted-key store: {exc}")

register_tab, manage_tab = st.tabs(
    ["Register / replace key", "View / revoke trusted keys"]
)

with register_tab:
    if not approved_senders:
        st.info(
            "There are no approved sender accounts yet. Approve a sender registration first."
        )
    else:
        sender_names = [user["username"] for user in approved_senders]
        selected_sender = st.selectbox("Approved sender account", sender_names)
        uploaded_key = st.file_uploader(
            "Upload sender signing public key (.pem)",
            type=["pem", "pub"],
            accept_multiple_files=False,
            help="Upload sender/keys/sender_sign_public.pem. Do not upload sender_sign_private.pem.",
        )

        existing_entry = trusted_entries.get(selected_sender)
        if existing_entry:
            st.warning(
                "This sender already has a trusted key. Registering another key will replace it."
            )
            st.caption(
                f"Current fingerprint: {existing_entry.get('fingerprint', 'Unavailable')}"
            )

        if uploaded_key is not None:
            try:
                key_bytes = uploaded_key.getvalue()
                uploaded_fingerprint = validate_sender_signing_key(key_bytes)
                st.code(uploaded_fingerprint, language=None)
                st.caption("Validated public key: EC / SECP256K1.")
                confirmation = st.checkbox(
                    "I independently verified that this public key belongs to this sender.",
                    key=f"confirm_key_{selected_sender}",
                )
                if st.button(
                    "Register trusted key"
                    if not existing_entry
                    else "Replace trusted key",
                    type="primary",
                    key=f"provision_{selected_sender}",
                    disabled=not confirmation,
                ):
                    # The explicit checkbox records the administrator's confirmation.
                    provision_trusted_key(
                        selected_sender,
                        key_bytes,
                        administrator_confirmed=confirmation,
                    )
                    action = (
                        "trusted_sender_key_replaced"
                        if existing_entry
                        else "trusted_sender_key_registered"
                    )
                    api_client.log_event(
                        st.session_state.admin_api_token,
                        action,
                        f"sender={selected_sender}; fingerprint={uploaded_fingerprint}",
                    )
                    st.success(f"Trusted signing key saved for {selected_sender}.")
                    st.rerun()
            except (ValueError, TypeError, UnicodeDecodeError, OSError) as exc:
                st.error(f"Key was not registered: {exc}")

with manage_tab:
    try:
        trusted_entries = load_trusted_keys(Path(TRUST_STORE))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        trusted_entries = {}
        st.error(f"Could not read the trusted-key store: {exc}")

    if not trusted_entries:
        st.info("No trusted sender keys are registered.")
    else:
        for trusted_username, entry in sorted(trusted_entries.items()):
            with st.container(border=True):
                left, right = st.columns([4, 1])
                left.markdown(f"**{trusted_username}**")
                left.caption(
                    f"Fingerprint: `{entry.get('fingerprint', 'Unavailable')}`"
                )
                if right.button("Revoke key", key=f"revoke_key_{trusted_username}"):
                    st.session_state[f"confirm_revoke_{trusted_username}"] = True

                if st.session_state.get(f"confirm_revoke_{trusted_username}", False):
                    st.warning(
                        "Revoking this key prevents packages signed by this key "
                        "from passing trusted-sender verification."
                    )
                    confirm_revoke = st.checkbox(
                        f"Confirm revocation for {trusted_username}",
                        key=f"checkbox_revoke_{trusted_username}",
                    )
                    if st.button(
                        "Confirm revoke",
                        key=f"confirm_revoke_button_{trusted_username}",
                        disabled=not confirm_revoke,
                    ):
                        if remove_trusted_key(trusted_username):
                            api_client.log_event(
                                st.session_state.admin_api_token,
                                "trusted_sender_key_revoked",
                                f"sender={trusted_username}; fingerprint={entry.get('fingerprint', '')}",
                            )
                            st.success(f"Trusted key revoked for {trusted_username}.")
                        st.session_state[f"confirm_revoke_{trusted_username}"] = False
                        st.rerun()

st.divider()
st.subheader("Client access management")
for user in users:
    if user["role"] == "admin":
        continue
    with st.container(border=True):
        col1, col2, col3 = st.columns([3, 2, 4])
        col1.write(f"**{user['username']}** · {user['role']}")
        col2.write(f"Status: **{user['status']}**")
        if user["status"] != "revoked":
            if col3.button("Revoke access", key=f"revoke_access_{user['username']}"):
                api_client.review_peer(st.session_state.admin_api_token, user["username"], "revoked")
                api_client.log_event(
                    st.session_state.admin_api_token,
                    "client_access_revoked",
                    f"username={user['username']}",
                )
                # Revoking a sender account also removes its signing-key trust.
                # Re-approval does not automatically restore trust; the admin
                # must independently verify and register the key again.
                if user["role"] == "sender" and remove_trusted_key(user["username"]):
                    api_client.log_event(
                        st.session_state.admin_api_token,
                        "trusted_sender_key_revoked",
                        f"sender={user['username']}; reason=sender_account_revoked",
                    )
                st.rerun()
        elif col3.button("Re-approve", key=f"reapprove_{user['username']}"):
            api_client.review_peer(st.session_state.admin_api_token, user["username"], "approved")
            st.rerun()

st.divider()
st.subheader("Audit events")
events = api_client.admin_events(st.session_state.admin_api_token)
if events:
    st.dataframe(events, use_container_width=True, hide_index=True)
else:
    st.info("No audit events yet.")

st.caption(
    "Private keys are never shown in this console. Account data is stored in "
    "backend/users.sqlite3. The trusted sender-key store is local runtime state "
    "and must not be committed to Git."
)
