import bcrypt from "bcrypt-nodejs";
import crypto from "crypto";
import mongoose from "mongoose";
import { NextFunction } from "express";
import * as _ from "lodash";

export type UserDocument = mongoose.Document & {
  username: string,
  password: string,
  email: string,
  phone: string,
  userType: string,
  level: number,
  registerDate: Date,
  updateAt: Date,
  isActive: boolean,

  comparePassword: comparePasswordFunction,
  gravatar: (size: number) => string
};

type comparePasswordFunction = (candidatePassword: string, cb: (err: any, isMatch: any) => {}) => void;

export type AuthToken = {
  accessToken: string,
  kind: string
};

const userSchema = new mongoose.Schema({
  username: {type: String, unique: true, required: true},
  password: {type: String},
  email: { type: String, unique: true, required: true },
  phone: { type: String, unique: true, required: true },
  userType: { type: String, default: "normal" },
  level: { type: Number, required: true },
  registerDate: { type: Date, default: new Date() },
  updateAt: { type: Date },
  isActive: { type: Boolean, default: false },
}, { timestamps: true });

/**
 * Password hash middleware.
 */
userSchema.pre("save", function save(next: NextFunction) {
  const user = this as UserDocument;
  if (!user.isModified("password")) { return next(); }

  bcrypt.genSalt(10, (err, salt) => {
    if (err) { return next(err); }
    bcrypt.hash(_.get(user, "password"), salt, undefined, (err: mongoose.Error, hash) => {
      if (err) { return next(err); }
      user.password = hash;
      next();
    });
  });
});

const comparePassword: comparePasswordFunction = function (candidatePassword, cb) {
  bcrypt.compare(candidatePassword, this.password, (err: mongoose.Error, isMatch: boolean) => {
    cb(err, isMatch);
  });
};

userSchema.methods.comparePassword = comparePassword;

/**
 * Helper method for getting user's gravatar.
 */
userSchema.methods.gravatar = function (size: number) {
  if (!size) {
    size = 200;
  }
  if (!this.email) {
    return `https://gravatar.com/avatar/?s=${size}&d=retro`;
  }
  const md5 = crypto.createHash("md5").update(this.email).digest("hex");
  return `https://gravatar.com/avatar/${md5}?s=${size}&d=retro`;
};

export const User = mongoose.model<UserDocument>("User", userSchema);
