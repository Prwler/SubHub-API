import jwt from 'jsonwebtoken';
import {JWT_SECRET} from '../config/env.js';
import User from "../models/user.model.js";

const authorize = async (req, res, next) => {
  try {
    let token;

    //console.log("Authorization Header:", req.headers.authorization); // Debugging log

    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith("Bearer")
    ) {
      token = req.headers.authorization.split(" ")[1];
    }

    //console.log("Extracted Token:", token); // Debugging log

    if (!token)
      return res
        .status(401)
        .json({ message: "Unauthorized - No Token Provided" });

    const decoded = jwt.verify(token, JWT_SECRET);
    //console.log("Decoded Token:", decoded);

    const user = await User.findById(decoded.userId); // Use decoded.userId instead of decoded.id
    if (!user)
      return res.status(401).json({ message: "Unauthorized - User Not Found" });

    req.user = user;
    next();

  } catch (error) {
    console.error("Auth Error:", error); // Debugging log
    res.status(401).json({ message: "Unauthorized", error: error.message });
  }
};


export default authorize;