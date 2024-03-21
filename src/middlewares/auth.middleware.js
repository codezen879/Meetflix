import { asyncHandler } from "../utils/asyncHandler.js";
import { User } from "../models/user.model.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";

export const verifyJWT = asyncHandler(async (req, res, next) => {
  try {
    const token =
      req.cookies?.accessToken ||
      req.header("Authorization")?.replace("Bearer", "");
    if (!token) {
      return res
        .status(401)
        .json(new ApiResponse(401, {}, "UnAuthorized Request!", "false"));
    }

    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    const user = await User.findById(decodedToken?._id).select(
      "-password -refreshToken"
    );

    if (!user) {
      return res
        .status(201)
        .json(new ApiResponse(401, {}, "Invalid Token!!", "false"));
    }

    req.user = user;
    next();
  } catch (error) {
    return res
      .status(201)
      .json(
        new ApiResponse(
          401,
          {},
          error?.message || "Invalid Access Token",
          "false"
        )
      );
  }
});
