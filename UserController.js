import {db} from "../configs/db.js"
import {z} from "zod"
import response  from "../utils/response.js"
import bcrypt from 'bcrypt';

const userSchema = z.object({
    uuid: z.string().length(36).optional(),
    email: z.string().email({ message: "Invalid email address" }),
    nik: z.string().length(16),
    username: z.string(),
    password: z.string(),
    createdAt: z.string().datetime({ message: "Invalid datetime string! Must be UTC." }).optional(),
    updatedAt: z.string().datetime({ message: "Invalid datetime string! Must be UTC." }).optional(),
    alamat: z.string(),
    kecamatan: z.string().length(7),
    kelurahan: z.string().length(10),
    tgl_lahir: z.string().optional(),
    uuid_instansi: z.string().length(36),
    role: z.string(),
    base_url: z.string(),
})

export const getUsers = async(req, res) => {
  try{
    let users = await db.user.findMany({
      where: {
        deletedAt: null
      }, 
      orderBy: {
        createdAt: 'desc'
      }
    })
    if(users.length == 0) {
      return response.custom(res, {
        code: 400,
        message: "Users is empty."
      })
    }
    return response.success(res, {
      code: 200,
      data: users,
      message: "Get all users succesfully."
    })
  }catch(e){
    return response.error(res, {
      code: 400,
      message: e.message,
      description: "Error getting all users."
    })
  }
}

export const getByIdUsers = async(req, res) => {
  const {id} = req.params;
  try{
    const users = await db.user.findFirst({
      where: {
        deletedAt: null,
        uuid: id
      }, 
      orderBy: {
        createdAt: 'desc'
      }
    })
    if(!users) {
      return response.custom(res, {
        code: 400,
        message: "Users is empty."
      })
    }
    return response.success(res, {
      code: 200,
      data: users,
      message: "Get all users succesfully."
    })
  }catch(e){
    return response.error(res, {
      code: 400,
      message: e.message,
      description: "Error getting all users."
    })
  }
}

export const createUser = async (req, res) => {
  try{
    const {password,...UserData } = userSchema.parse(req.body);
    console.log(req.body);

    const hashedPassword = await bcrypt.hash(password, 10);
    const create = await  db.user.create({
      data: {
        ...UserData,
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
          description: "Failed to create data User."
        });
      }
  }
}

export const updateUser = async(req, res) => {
  const {id} = req.params
  try{
    const idValid = await db.user.findFirst({where: {uuid: id}})
    if(!idValid) return response.custom(res, {code: 404, message: "Failed to update data user. invalid id user."})
    const {password,...UserData } = userSchema.parse(req.body);

    // const user = userSchema.parse(req.body)
    const update = await db.user.update({
      where: {uuid : id},
      data: {
        ...UserData,
        password: hashedPassword,
      }
    })

    response.success(res, {
      code: 200,
      length: 1,
      data: update,
      message: `Data user updated succesfully.`
    })
  }catch(e){
    if (e instanceof z.ZodError) {
      response.error(res, {
        code: 406,
        message: e.errors,
        description: `Input tidak valid.`,
        detail: `${e.errors[0].path[0]} -> ${e.errors[0].message}.`
      });
    } else {
      response.error(res, {
        code: 400,
        message: e.message,
        description: "Failed to update data user."
      });
    }
  }
}

export const deleteUser = async( req, res ) => {
  const {id} = req.params
  try{
    const idValid = await db.user.findFirst({where: {uuid: id, deletedAt: null}})
    if(!idValid) return response.custom(res, {code: 404, message: "Failed to delete data user. invalid id user."})
    const deleted = await db.user.update({
      where: {uuid : id},
      data: {
        deletedAt: new Date().toISOString()
      }
    })
    response.success(res, {
      code: 200,
      length: 1,
      data: deleted,
      message: `Data role deleted succesfully.`
    })
  }catch(e){
    if (e instanceof z.ZodError) {
      response.error(res, {
        code: 406,
        message: e.errors,
        description: `Input tidak valid.`,
        detail: `${e.errors[0].path[0]} -> ${e.errors[0].message}.`
      });
    } else {
      response.error(res, {
        code: 400,
        message: e.message,
        description: "Failed to delete data role."
      });
    }
  }
}

