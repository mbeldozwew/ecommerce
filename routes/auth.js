const express= require("express");
const router = express.Router();


const {signup, signin, signout, requireSignin,accountActivation, forgotPassword, resetPassword, googleLogin} = require("../controllers/auth")
const {userSignupValidator, userSigninValidator, forgotPasswordValidator, resetPasswordValidator}=require("../validator/auth")
const {runValidation}=require('../validator/index')


router.post("/signup", userSignupValidator,runValidation, signup);
router.post("/account-activation", accountActivation)
router.post("/signin", signin, userSigninValidator, runValidation);
router.get("/signout", signout);
// forgot reset password
router.put('/forgot-password', forgotPasswordValidator, runValidation, forgotPassword);
router.put('/reset-password', resetPasswordValidator, runValidation, resetPassword);

router.post('/google-login', googleLogin);

module.exports=router;
