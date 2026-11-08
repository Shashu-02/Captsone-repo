"""Authenticated Admin console for account and trusted-sender management."""
from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

import api_client
from trusted_keys import fingerprint, validate_signing_public_key

st.set_page_config(page_title="Secure Storage Admin", page_icon="🛡️", layout="wide")
st.title("🛡️ Secure Storage — Admin Console")
st.caption("Approve clients, manage trusted sender identities, control access, and review audit events.")

if "admin_user" not in st.session_state:
    st.session_state.admin_user = None
if "admin_api_token" not in st.session_state:
    st.session_state.admin_api_token = None

if not st.session_state.admin_user or not st.session_state.admin_api_token:
    with st.form("admin_login"):
        username_input = st.text_input("Administrator username")
        password_input = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Sign in")
    if submitted:
        try:
            result = api_client.login(username_input, password_input)
            user = result["user"]
            if user.get("role") != "admin":
                st.error("This account is not an administrator.")
            else:
                st.session_state.admin_user = user["username"]
                st.session_state.admin_api_token = result["access_token"]
                st.rerun()
        except Exception as exc:
            st.error(str(exc))
    st.info("Use the existing administrator account. The first admin is created from a terminal only when no admin exists.")
    st.stop()

token = st.session_state.admin_api_token
try:
    current_user = api_client.me(token)
    if current_user.get("role") != "admin":
        raise api_client.APIError("Administrator access required.")
except Exception as exc:
    st.session_state.admin_user = None
    st.session_state.admin_api_token = None
    st.error(f"Admin session is no longer valid: {exc}")
    st.stop()

if st.button("Sign out"):
    try:
        api_client.log_event(token, "logout", "admin console")
    except Exception:
        pass
    st.session_state.admin_user = None
    st.session_state.admin_api_token = None
    st.rerun()

admin_username = current_user["username"]
st.success(f"Signed in as administrator: {admin_username}")

try:
    users = api_client.admin_peers(token)
    trusted_entries = api_client.admin_trusted_keys(token)
    events = api_client.admin_events(token)
except Exception as exc:
    st.error(f"Could not load Admin data from central API: {exc}")
    st.stop()

pending_users = [u for u in users if u["status"] == "pending"]
approved_senders = [u for u in users if u["role"] == "sender" and u["status"] == "approved"]
trusted_by_name = {entry["username"]: entry for entry in trusted_entries}

st.subheader(f"Pending registrations ({len(pending_users)})")
if not pending_users:
    st.write("No pending registrations.")
for user in pending_users:
    with st.container(border=True):
        c1, c2, c3 = st.columns([3, 2, 3])
        c1.markdown(f"**{user['username']}**")
        c1.caption(f"Role: {user['role']} · Registered: {user['created_at']}")
        if c2.button("Approve", key=f"approve_{user['username']}", type="primary"):
            try:
                api_client.review_peer(token, user["username"], "approved")
                st.rerun()
            except Exception as exc:
                st.error(str(exc))
        if c3.button("Reject", key=f"reject_{user['username']}"):
            try:
                api_client.review_peer(token, user["username"], "rejected")
                st.rerun()
            except Exception as exc:
                st.error(str(exc))

st.divider()
st.header("Trusted sender signing keys")
st.write(
    "Register only approved sender accounts. Independently verify the displayed "
    "SHA-256 fingerprint through a separate trusted channel before confirming. "
    "Upload only the public signing key; never upload a private key."
)
st.caption("Trusted keys are stored centrally in backend/users.sqlite3 and managed through authenticated FastAPI endpoints.")

register_tab, manage_tab = st.tabs(["Register / replace key", "View / revoke trusted keys"])

with register_tab:
    if not approved_senders:
        st.info("There are no approved sender accounts yet. Approve a sender first.")
    else:
        sender_names = [u["username"] for u in approved_senders]
        selected_sender = st.selectbox("Approved sender account", sender_names)
        uploaded_key = st.file_uploader(
            "Upload sender signing public key (.pem)",
            type=["pem", "pub"],
            accept_multiple_files=False,
            help="Upload sender/keys/sender_sign_public.pem. Do not upload sender_sign_private.pem.",
        )
        existing = trusted_by_name.get(selected_sender)
        if existing:
            st.warning("This sender already has a trusted key. Registering another key will replace it.")
            st.caption(f"Current fingerprint: {existing['fingerprint']}")
        if uploaded_key is not None:
            try:
                key_bytes = uploaded_key.getvalue()
                pem_text, uploaded_fp = validate_signing_public_key(key_bytes)
                st.code(uploaded_fp, language=None)
                st.caption("Validated public key: EC / SECP256K1.")
                confirmation = st.checkbox(
                    "I independently verified that this fingerprint belongs to this sender.",
                    key=f"confirm_key_{selected_sender}_{uploaded_fp}",
                )
                if st.button(
                    "Register trusted key" if not existing else "Replace trusted key",
                    type="primary",
                    disabled=not confirmation,
                    key=f"register_key_{selected_sender}",
                ):
                    result = api_client.register_trusted_key(
                        token, selected_sender, pem_text, confirmation
                    )
                    st.success(f"Trusted signing key {result['action'].replace('_', ' ')} for {selected_sender}.")
                    st.rerun()
            except Exception as exc:
                st.error(f"Key was not registered: {exc}")

with manage_tab:
    if not trusted_entries:
        st.info("No trusted sender keys are registered.")
    else:
        for entry in trusted_entries:
            username = entry["username"]
            with st.container(border=True):
                left, right = st.columns([4, 1])
                left.markdown(f"**{username}**")
                left.caption(f"Fingerprint: `{entry['fingerprint']}`")
                left.caption(f"Registered by: {entry['registered_by']} · Updated: {entry['updated_at']}")
                if right.button("Revoke key", key=f"revoke_key_{username}"):
                    st.session_state[f"confirm_revoke_{username}"] = True
                if st.session_state.get(f"confirm_revoke_{username}", False):
                    st.warning("Revocation immediately prevents this key from passing Receiver trust verification.")
                    confirm = st.checkbox(f"Confirm revocation for {username}", key=f"confirm_box_{username}")
                    if st.button("Confirm revoke", key=f"confirm_revoke_{username}_button", disabled=not confirm):
                        try:
                            api_client.revoke_trusted_key(token, username)
                            st.session_state[f"confirm_revoke_{username}"] = False
                            st.success(f"Trusted key revoked for {username}.")
                            st.rerun()
                        except Exception as exc:
                            st.error(str(exc))

st.divider()
st.subheader("Client access management")
for user in users:
    if user["role"] == "admin":
        continue
    with st.container(border=True):
        c1, c2, c3 = st.columns([3, 2, 4])
        c1.write(f"**{user['username']}** · {user['role']}")
        c2.write(f"Status: **{user['status']}**")
        if user["status"] != "revoked":
            if c3.button("Revoke access", key=f"revoke_access_{user['username']}"):
                try:
                    # Sender-key revocation is performed in the same SQLite transaction.
                    api_client.review_peer(token, user["username"], "revoked")
                    st.rerun()
                except Exception as exc:
                    st.error(str(exc))
        elif c3.button("Re-approve", key=f"reapprove_{user['username']}"):
            try:
                api_client.review_peer(token, user["username"], "approved")
                st.rerun()
            except Exception as exc:
                st.error(str(exc))

st.divider()
st.subheader("Audit events")
if events:
    st.dataframe(events, use_container_width=True, hide_index=True)
else:
    st.info("No audit events yet.")
st.caption("Private keys are never shown. Accounts and trusted sender identities are stored in backend/users.sqlite3.")
