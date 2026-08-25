import { Request } from "express";

export interface AuthRequest<
  P = {},
  ResBody = any,
  ReqBody = any,
> extends Request<P, ResBody, ReqBody> {
  user: {
    userId: number;
    email: string;
  };
}

export interface User {
  id: number;
  email: string;
  password: string;
}
