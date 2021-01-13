import { createAction } from '@reduxjs/toolkit';
import { put, takeLatest, call } from 'redux-saga/effects';
import { url } from '../../apiConfig';
import {
  onLoadingUserFarmsStart,
  onLoadingUserFarmsFail,
  acceptInvitationSuccess,
} from '../userFarmSlice';
import history from '../../history';
import { loginSuccess } from '../userFarmSlice';
import { toastr } from 'react-redux-toastr';
import { getFirstNameLastName } from '../../util';
import { purgeState } from '../../index';
import { enterInvitationFlow } from './invitationSlice';

const axios = require('axios');
const acceptInvitationWithSSOUrl = () => `${url}/user/accept_invitation`;
const acceptInvitationWithLiteFarmUrl = () => `${url}/user/accept_invitation`;

export const acceptInvitationWithSSO = createAction(`acceptInvitationWithSSOSaga`);

export function* acceptInvitationWithSSOSaga({
  payload: { google_id_token, invite_token, user: userForm },
}) {
  try {
    yield put(onLoadingUserFarmsStart());
    const header = {
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer ' + google_id_token,
      },
    };
    const user = {
      ...userForm,
      language_preference: localStorage.getItem('litefarm_lang'),
      ...getFirstNameLastName(userForm.name),
    };
    delete user.name;
    const result = yield call(
      axios.put,
      acceptInvitationWithSSOUrl(),
      { invite_token, ...user },
      header,
    );
    const { id_token, user: resUser } = result.data;
    localStorage.setItem('id_token', id_token);
    purgeState();
    yield put(acceptInvitationSuccess(resUser));
    yield put(enterInvitationFlow());
    history.push('/consent');
  } catch (e) {
    yield put(onLoadingUserFarmsFail(e));
    history.push('/expired', 'INVITATION');
    toastr.error(this.props.t('message:LOGIN.ERROR.LOGIN_FAIL'));
  }
}

export const acceptInvitationWithLiteFarm = createAction(`acceptInvitationWithLiteFarmSaga`);

export function* acceptInvitationWithLiteFarmSaga({ payload: { invite_token, user: userForm } }) {
  try {
    yield put(onLoadingUserFarmsStart());
    const header = {
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer ' + invite_token,
      },
    };
    const user = {
      ...userForm,
      language_preference: localStorage.getItem('litefarm_lang'),
      ...getFirstNameLastName(userForm.name),
    };
    delete user.name;
    const result = yield call(axios.post, acceptInvitationWithLiteFarmUrl(), user, header);
    const { id_token, user: resUser } = result.data;
    localStorage.setItem('id_token', id_token);
    purgeState();
    yield put(acceptInvitationSuccess(resUser));
    yield put(enterInvitationFlow());
    history.push('/consent');
  } catch (e) {
    yield put(onLoadingUserFarmsFail(e));
    history.push('/expired', 'INVITATION');
    toastr.error(this.props.t('message:LOGIN.ERROR.LOGIN_FAIL'));
  }
}

export default function* inviteSaga() {
  yield takeLatest(acceptInvitationWithSSO.type, acceptInvitationWithSSOSaga);
  yield takeLatest(acceptInvitationWithLiteFarm.type, acceptInvitationWithLiteFarmSaga);
}