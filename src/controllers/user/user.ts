import async from "async";
import crypto from "crypto";
import nodemailer from "nodemailer";
import passport from "passport";
import { User, UserDocument, AuthToken } from "../../models/User";
import { Request, Response, NextFunction } from "express";
import { IVerifyOptions } from "passport-local";
import { WriteError } from "mongodb";
import "../../config/passport";

/**
 * POST /login
 * Sign in using email and password.
 */
export let postLogin = (req: Request, res: Response, next: NextFunction) => {

  const errors = req.validationErrors();

  if (errors) {
    req.flash("errors", errors);
    return res.redirect("/login");
  }

  passport.authenticate("local", (err: Error, user: UserDocument, info: IVerifyOptions) => {
    if (err) { return next(err); }
    if (!user) {
      req.flash("errors", info.message);
      return res.redirect("/login");
    }
    req.logIn(user, (err) => {
      if (err) { return next(err); }
      req.flash("success", { msg: "Success! You are logged in." });
      res.redirect(req.session.returnTo || "/");
    });
  })(req, res, next);
};


/**
 * POST /signup
 * Create a new local account.
 */
export let register = (req: Request, res: Response, next: NextFunction) => {
  const errors = {} as UserDocument;

  const { username, password, email, phone, userType, level } = req.body;
  User.findOne({ $or: [{username, email}]})
    .then(user => {
      if (user) {
        if (user.username === username)  errors.username = "Username đã tồn tại";
        if (user.email === email) errors.email = "Email đã tồn tại";
        if (user.phone === phone) errors.phone = "Phone đã tồn tại";

        return res.status(400).json(errors);
      }

      const newUser = new User({
        username, password, email, phone, userType, level
      });
      newUser.save()
      .then((user: UserDocument) => {
        res.status(200).json(user);
      })
      .catch(err => res.status(400).json(err));
    })
    .catch(err => res.status(400).json(err));
};

// /**
//  * GET /account
//  * Profile page.
//  */
// export let getAccount = (req: Request, res: Response) => {
//   res.render("account/profile", {
//     title: "Account Management"
//   });
// };

// /**
//  * POST /account/profile
//  * Update profile information.
//  */
// export let postUpdateProfile = (req: Request, res: Response, next: NextFunction) => {

//   const errors = req.validationErrors();

//   if (errors) {
//     req.flash("errors", errors);
//     return res.redirect("/account");
//   }

//   User.findById(req.user.id, (err, user: UserDocument) => {
//     if (err) { return next(err); }
//     user.email = req.body.email || "";
//     user.profile.name = req.body.name || "";
//     user.profile.gender = req.body.gender || "";
//     user.profile.location = req.body.location || "";
//     user.profile.website = req.body.website || "";
//     user.save((err: WriteError) => {
//       if (err) {
//         if (err.code === 11000) {
//           req.flash("errors", { msg: "The email address you have entered is already associated with an account." });
//           return res.redirect("/account");
//         }
//         return next(err);
//       }
//       req.flash("success", { msg: "Profile information has been updated." });
//       res.redirect("/account");
//     });
//   });
// };

// /**
//  * POST /account/password
//  * Update current password.
//  */
// export let postUpdatePassword = (req: Request, res: Response, next: NextFunction) => {
//   const errors = req.validationErrors();

//   if (errors) {
//     req.flash("errors", errors);
//     return res.redirect("/account");
//   }

//   User.findById(req.user.id, (err, user: UserDocument) => {
//     if (err) { return next(err); }
//     user.password = req.body.password;
//     user.save((err: WriteError) => {
//       if (err) { return next(err); }
//       req.flash("success", { msg: "Password has been changed." });
//       res.redirect("/account");
//     });
//   });
// };

// /**
//  * POST /account/delete
//  * Delete user account.
//  */
// export let postDeleteAccount = (req: Request, res: Response, next: NextFunction) => {
//   User.remove({ _id: req.user.id }, (err) => {
//     if (err) { return next(err); }
//     req.logout();
//     req.flash("info", { msg: "Your account has been deleted." });
//     res.redirect("/");
//   });
// };

// /**
//  * GET /account/unlink/:provider
//  * Unlink OAuth provider.
//  */
// export let getOauthUnlink = (req: Request, res: Response, next: NextFunction) => {
//   const provider = req.params.provider;
//   User.findById(req.user.id, (err, user: any) => {
//     if (err) { return next(err); }
//     user[provider] = undefined;
//     user.tokens = user.tokens.filter((token: AuthToken) => token.kind !== provider);
//     user.save((err: WriteError) => {
//       if (err) { return next(err); }
//       req.flash("info", { msg: `${provider} account has been unlinked.` });
//       res.redirect("/account");
//     });
//   });
// };

// /**
//  * GET /reset/:token
//  * Reset Password page.
//  */
// export let getReset = (req: Request, res: Response, next: NextFunction) => {
//   if (req.isAuthenticated()) {
//     return res.redirect("/");
//   }
//   User
//     .findOne({ passwordResetToken: req.params.token })
//     .where("passwordResetExpires").gt(Date.now())
//     .exec((err, user) => {
//       if (err) { return next(err); }
//       if (!user) {
//         req.flash("errors", { msg: "Password reset token is invalid or has expired." });
//         return res.redirect("/forgot");
//       }
//       res.render("account/reset", {
//         title: "Password Reset"
//       });
//     });
// };

// /**
//  * POST /reset/:token
//  * Process the reset password request.
//  */
// export let postReset = (req: Request, res: Response, next: NextFunction) => {
//   const errors = req.validationErrors();

//   if (errors) {
//     req.flash("errors", errors);
//     return res.redirect("back");
//   }

//   async.waterfall([
//     function resetPassword(done: Function) {
//       User
//         .findOne({ passwordResetToken: req.params.token })
//         .where("passwordResetExpires").gt(Date.now())
//         .exec((err, user: any) => {
//           if (err) { return next(err); }
//           if (!user) {
//             req.flash("errors", { msg: "Password reset token is invalid or has expired." });
//             return res.redirect("back");
//           }
//           user.password = req.body.password;
//           user.passwordResetToken = undefined;
//           user.passwordResetExpires = undefined;
//           user.save((err: WriteError) => {
//             if (err) { return next(err); }
//             req.logIn(user, (err) => {
//               done(err, user);
//             });
//           });
//         });
//     },
//     function sendResetPasswordEmail(user: UserDocument, done: Function) {
//       const transporter = nodemailer.createTransport({
//         service: "SendGrid",
//         auth: {
//           user: process.env.SENDGRID_USER,
//           pass: process.env.SENDGRID_PASSWORD
//         }
//       });
//       const mailOptions = {
//         to: user.email,
//         from: "express-ts@starter.com",
//         subject: "Your password has been changed",
//         text: `Hello,\n\nThis is a confirmation that the password for your account ${user.email} has just been changed.\n`
//       };
//       transporter.sendMail(mailOptions, (err) => {
//         req.flash("success", { msg: "Success! Your password has been changed." });
//         done(err);
//       });
//     }
//   ], (err) => {
//     if (err) { return next(err); }
//     res.redirect("/");
//   });
// };

// /**
//  * GET /forgot
//  * Forgot Password page.
//  */
// export let getForgot = (req: Request, res: Response) => {
//   if (req.isAuthenticated()) {
//     return res.redirect("/");
//   }
//   res.render("account/forgot", {
//     title: "Forgot Password"
//   });
// };

// /**
//  * POST /forgot
//  * Create a random token, then the send user an email with a reset link.
//  */
// export let postForgot = (req: Request, res: Response, next: NextFunction) => {
//   const errors = req.validationErrors();

//   if (errors) {
//     req.flash("errors", errors);
//     return res.redirect("/forgot");
//   }

//   async.waterfall([
//     function createRandomToken(done: Function) {
//       crypto.randomBytes(16, (err, buf) => {
//         const token = buf.toString("hex");
//         done(err, token);
//       });
//     },
//     function setRandomToken(token: AuthToken, done: Function) {
//       User.findOne({ email: req.body.email }, (err, user: any) => {
//         if (err) { return done(err); }
//         if (!user) {
//           req.flash("errors", { msg: "Account with that email address does not exist." });
//           return res.redirect("/forgot");
//         }
//         user.passwordResetToken = token;
//         user.passwordResetExpires = Date.now() + 3600000; // 1 hour
//         user.save((err: WriteError) => {
//           done(err, token, user);
//         });
//       });
//     },
//     function sendForgotPasswordEmail(token: AuthToken, user: UserDocument, done: Function) {
//       const transporter = nodemailer.createTransport({
//         service: "SendGrid",
//         auth: {
//           user: process.env.SENDGRID_USER,
//           pass: process.env.SENDGRID_PASSWORD
//         }
//       });
//       const mailOptions = {
//         to: user.email,
//         from: "hackathon@starter.com",
//         subject: "Reset your password on Hackathon Starter",
//         text: `You are receiving this email because you (or someone else) have requested the reset of the password for your account.\n\n
//           Please click on the following link, or paste this into your browser to complete the process:\n\n
//           http://${req.headers.host}/reset/${token}\n\n
//           If you did not request this, please ignore this email and your password will remain unchanged.\n`
//       };
//       transporter.sendMail(mailOptions, (err) => {
//         req.flash("info", { msg: `An e-mail has been sent to ${user.email} with further instructions.` });
//         done(err);
//       });
//     }
//   ], (err) => {
//     if (err) { return next(err); }
//     res.redirect("/forgot");
//   });
// };
