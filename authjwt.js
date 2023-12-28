import jwt from "jsonwebtoken";
import config from "../configs/auth.js";
import {db} from "../configs/db.js"

const { TokenExpiredError } = jwt;

const catchError = (err, res) => {
    if (err instanceof TokenExpiredError) {
        return res.status(401).send({ message: "Unauthorized! Access Token was expired!" });
    }
    return res.sendStatus(401).send({ message: "Unauthorized!" });
}

const verifyToken = (req, res, next) => {
    let token = req.headers["x-access-token"];

    if (!token) {
        return res.status(403).send({
        message: "No token provided!"
        });
    }

    jwt.verify(token,
            config.secret,
            (err, decoded) => {
                if (err) {
                    return catchError(err, res);
                }
                req.userId = decoded.id;
                console.log(req.userId);
                next();
    });
};

const isAuthorized = (req, res, next) => {
  // User.find(req)
  // console.log(req.originalUrl);
  // console.log(req.userId);
  console.log(req.userId);
  db.user.findOne({ where: {
    uuid: req.userId
  }})
//   .then(user => {
//     db.role.findOne({where: {
//       uuid: db.role
//     }})
//     .then(role => {

//         db.
//         // console.log(role);
        
//     //   const permission = JSON.parse(role.permission);
//     // //   console.log(permission);
//     //   if(!permission){
//     //     return res.status(404).send({ message: "Unauthorized." });
        
//     //     // if(req.originalUrl)
//     //   }
//     //   const url = Feature.findOne({
//     //     where:{
//     //       url: req.originalUrl
//     //     },
//     //   })
//     //   .then(feature => {
//     //     console.log(feature);
//     //     if (!feature) {
//     //       return res.status(404).send({ message: "Unauthorized." });
//     //     }
//     //     next();
//     //     return;
//     //   })
//       // console.log(permissionObject);
      
//     })
//   })
  // Role.findOne()
};

// isAdmin = (req, res, next) => {
//   User.findByPk(req.userId).then(user => {
//     user.getRoles().then(roles => {
//       for (let i = 0; i < roles.length; i++) {
//         if (roles[i].name === "admin") {
//           next();
//           return;
//         }
//       }

//       res.status(403).send({
//         message: "Require Admin Role!"
//       });
//       return;
//     });
//   });
// };

// isModerator = (req, res, next) => {
//   User.findByPk(req.userId).then(user => {
//     user.getRoles().then(roles => {
//       for (let i = 0; i < roles.length; i++) {
//         if (roles[i].name === "moderator") {
//           next();
//           return;
//         }
//       }

//       res.status(403).send({
//         message: "Require Moderator Role!"
//       });
//     });
//   });
// };

// isModeratorOrAdmin = (req, res, next) => {
//   User.findByPk(req.userId).then(user => {
//     user.getRoles().then(roles => {
//       for (let i = 0; i < roles.length; i++) {
//         if (roles[i].name === "moderator") {
//           next();
//           return;
//         }

//         if (roles[i].name === "admin") {
//           next();
//           return;
//         }
//       }

//       res.status(403).send({
//         message: "Require Moderator or Admin Role!"
//       });
//     });
//   });
// };

const authJwt = {
  verifyToken: verifyToken,
  isAuthorized: isAuthorized
};
module.exports = authJwt;