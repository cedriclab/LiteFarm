import express from 'express';
const router = express.Router();
import loginController from '../controllers/loginController.js';
import checkGoogleJwt from '../middleware/acl/checkGoogleJwt.js';

router.post('/google', checkGoogleJwt, loginController.loginWithGoogle());
router.post('/tokens', checkGoogleJwt, loginController.createSessionFromToken());
router.post('/', loginController.authenticateUser());
router.get('/user/:email', loginController.getUserNameByUserEmail());

export default router;
