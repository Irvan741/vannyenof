import {db} from "../configs/db.js"
import {z} from "zod"
import config from "../configs/auth.js"
// const config = require("../config/auth.config");
import response  from "../utils/response.js"
import { createToken, verifyExpiration } from "../utils/refreshToken.js";
import { PrismaClient } from "@prisma/client";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";

const authSchema = z.object({
    email: z.string(),
    nik: z.string(),
    username: z.string(),
    password: z.string(),
    alamat: z.string(),
    kecamatan: z.string(7),
    kelurahan: z.string().length(7),
    tgl_lahir: z.string(),
    uuid_instansi: z.string().length(36).optional(),
    role: z.string().length(36)
})
export const signup = async (req, res) => {
  // Save User to Database
//   console.log(req.body.email);

    // find user has same email
    try{
        const {password,...user } = authSchema.parse(req.body);
        const hashedPassword = await bcrypt.hash(password, 10);
        const checkEmail = await db.user.findFirst({
            where: {email: user.email}
        });
        if(checkEmail){
            return response.custom(res, {
                code: 401,
                message: "User Already Exists."
            })
        }

        const checkRole = await db.role.findFirst({
            where: {uuid: user.role}
        });
        if(checkRole == null){
            return response.custom(res, {
                code: 401,
                message: "Role not Valid."
            })
        }

        const checkInstansi = await db.instansi.findFirst({
            where: {uuid: user.role}
        });
        if(checkInstansi == null){
            return response.custom(res, {
                code: 401,
                message: "Instansi not Valid."
            })
        }

        const create = await  db.user.create({
            data: {
              ...user,
              password: hashedPassword,
            }
        })
        response.success(res, {
            code: 201,
            length: 1,
            data: create,
            message: "Data user created succesfully."
        })
    }catch(e){
        if (e instanceof z.ZodError) {
        response.error(res, {
            code: 406,
            message: e.errors,
            description: "Input tidak valid."
        });
        } else {
        response.error(res, {
            code: 400,
            message: e.message,
            description: "Failed to create data user."
        });
        }
    }    
};

export const signin = async (req, res) => {

    const user = await db.user.findFirst({
        where: {
          email: req.body.email,
        },
    });
      
    if (!user) {
        // User not found, handle accordingly
        return response.custom(res, {
            code: 401,
            message: "User Not Found."
        })
    }
    let passwordIsValid = bcrypt.compareSync(
        req.body.password,
        user.password
    );

    if (!passwordIsValid) {
        return res.status(401).send({
            accessToken: null,
            message: "Invalid Password!"
        });
    }
    
    let role = db.role.findFirst({
        where: { 
            uuid : user.role
        }
    });
    if(!role){
        return res.status(401).send({
            accessToken: null,
            message: "Role Invalid"
        })
    }
    const token = jwt.sign({ id: user.uuid }, config.secret, {
        expiresIn: config.jwtExpiration
    });
    // token.accessToken;
    // Set the access token as a cookie
    
    res.cookie('access_token', token, {
        httpOnly: true,
        maxAge: config.jwtExpiration * 1000, // Convert seconds to milliseconds
        secure: process.env.NODE_ENV === 'production', // Set to true if your app uses HTTPS
    });

    const prisma = new PrismaClient();

    let refreshToken = await createToken(prisma, user);
    return response.success(res, {
        code: 200,
        length: 1,
        data: {
            id: user.id,
                username: user.username,
                email: user.email,
                roles: role.uuid,
                accessToken: token,
                refreshToken: refreshToken,
        },
        message: "Logged in succesfully."
    });
    res.status(200).send({
                id: user.id,
                username: user.username,
                email: user.email,
                roles: role.uuid,
                accessToken: token,
                refreshToken: refreshToken,
    });
    

    

};


// module.exports = {
//     signupForm,
//     signup,
//     signin
// }