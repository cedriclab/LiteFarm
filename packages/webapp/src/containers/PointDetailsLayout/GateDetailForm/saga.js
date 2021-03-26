import { call, put, select, takeEvery } from 'redux-saga/effects';
import apiConfig from '../../../apiConfig';
import { loginSelector } from '../../userFarmSlice';
import { getHeader } from '../../saga';
import { createAction } from '@reduxjs/toolkit';
import { getLocationObjectFromGate, postGateSuccess } from '../../gateSlice';
import history from '../../../history';
import { canShowSuccessHeader, resetLocationData, setSuccessMessage } from '../../mapSlice';
import i18n from '../../../locales/i18n';

const axios = require('axios');
export const postGateLocation = createAction(`postGateLocationSaga`);

export function* postGateLocationSaga({ payload: data }) {
  const formData = data.formData;
  const { locationURL } = apiConfig;
  let { user_id, farm_id } = yield select(loginSelector);
  formData.farm_id = farm_id;
  const header = getHeader(user_id, farm_id);
  const locationObject = getLocationObjectFromGate(formData);

  try {
    const result = yield call(
      axios.post,
      `${locationURL}/${locationObject.figure.type}`,
      locationObject,
      header,
    );
    yield put(postGateSuccess(result.data));
    yield put(resetLocationData());
    yield put(
      setSuccessMessage([i18n.t('FARM_MAP.MAP_FILTER.GATE'), i18n.t('message:MAP.SUCCESS_POST')]),
    );
    yield put(canShowSuccessHeader(true));
    history.push({ pathname: '/map' });
  } catch (e) {
    history.push({
      path: history.location.pathname,
      state: {
        error: `${i18n.t('message:MAP.FAIL_POST')} ${i18n
          .t('FARM_MAP.MAP_FILTER.GATE')
          .toLowerCase()}`,
      },
    });
    console.log(e);
  }
}

export default function* gateLocationSaga() {
  yield takeEvery(postGateLocation.type, postGateLocationSaga);
}