import sys
from pathlib import Path
import streamlit as st
ROOT=Path(__file__).resolve().parents[1]
BACKEND=ROOT/'backend'
if str(BACKEND) not in sys.path: sys.path.insert(0,str(BACKEND))
import auth_manager
st.set_page_config(page_title='Secure Storage Admin',page_icon='🛡️',layout='wide')
st.title('🛡️ Secure Storage — Admin Console')
st.caption('Approve clients, manage access, and review audit events.')
if 'admin_user' not in st.session_state: st.session_state.admin_user=None
if not st.session_state.admin_user:
    with st.form('admin_login'):
        u=st.text_input('Administrator username')
        p=st.text_input('Password',type='password')
        ok=st.form_submit_button('Sign in')
    if ok:
        user=auth_manager.authenticate(u,p)
        if user and user['role']=='admin' and user['status']=='approved':
            st.session_state.admin_user=user['username']; st.rerun()
        st.error('Invalid administrator credentials.')
    st.info('Create the first admin from a terminal using: python backend/auth_manager.py create-admin')
    st.stop()
if st.button('Sign out'):
    auth_manager.log_event(st.session_state.admin_user,'logout','admin console')
    st.session_state.admin_user=None; st.rerun()
st.success(f"Signed in as administrator: {st.session_state.admin_user}")
users=auth_manager.list_users()
pending=[u for u in users if u['status']=='pending']
st.subheader(f'Pending registrations ({len(pending)})')
if not pending: st.write('No pending registrations.')
for u in pending:
    with st.container(border=True):
        c1,c2,c3=st.columns([3,2,3])
        c1.markdown(f"**{u['username']}**")
        c1.caption(f"Role: {u['role']} · Registered: {u['created_at']}")
        if c2.button('Approve',key=f"approve_{u['username']}",type='primary'):
            auth_manager.review_user(u['username'],'approved',st.session_state.admin_user)
            st.rerun()
        if c3.button('Reject',key=f"reject_{u['username']}"):
            auth_manager.review_user(u['username'],'rejected',st.session_state.admin_user)
            st.rerun()
st.divider(); st.subheader('Client access management')
for u in users:
    if u['role']=='admin': continue
    with st.container(border=True):
        c1,c2,c3=st.columns([3,2,4])
        c1.write(f"**{u['username']}** · {u['role']}")
        c2.write(f"Status: **{u['status']}**")
        if u['status']!='revoked':
            if c3.button('Revoke access',key=f"revoke_{u['username']}"):
                auth_manager.review_user(u['username'],'revoked',st.session_state.admin_user); st.rerun()
        elif c3.button('Re-approve',key=f"reapprove_{u['username']}"):
            auth_manager.review_user(u['username'],'approved',st.session_state.admin_user); st.rerun()
st.divider(); st.subheader('Audit events')
events=auth_manager.list_events()
if events: st.dataframe(events,use_container_width=True,hide_index=True)
else: st.info('No audit events yet.')
st.caption('Private keys are never shown in this console. This local demo stores account data in backend/users.sqlite3.')
