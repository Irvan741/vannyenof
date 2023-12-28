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
  console.log(token);

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
                next();
    });
};

const isAuthorized = (req, res, next) => {
  // User.find(req)
  // console.log(req.originalUrl);
  // console.log(req.userId);
  db.user.findFirst({ where: {
    uuid: req.userId
  }})
  .then(user => {
    db.role.findFirst({where: {
      uuid: user.role
    }})
    .then(role => {

        db.feature.findFirst({
            where: {
                name: req.originalUrl
            }
        }).then(feature => {
            // Check if the feature's UUID is in the role's permissions
            if (role && role.permission && role.permission.includes(feature.uuid)) {
                // Redirect to the original URL
                // res.redirect(req.originalUrl);
                next();
                return;
            } else {
                // Handle the case where the feature is not permitted
                // You might want to show an error message or redirect to a different URL
                res.status(403).send("Permission denied");
            }})
            .catch(error => {
                // Handle errors in finding the feature
                console.error("Error finding feature:", error);
                res.status(500).send("Internal Server Error");
            });
        })
        .catch(error => {
            // Handle errors in finding the role
            console.error("Error finding role:", error);
            res.status(500).send("Internal Server Error");
        });
    })
    .catch(error => {
        // Handle errors in finding the user
        console.error("Error finding user:", error);
        res.status(500).send("Internal Server Error");
    });
}


        
        // so i want here: the "role" has list of uuid of features in column permission (table role), it goes like this
        // 91db3c85-c118-4fc5-b4dc-26e9a332200f,01157e2d-2afc-4034-bf58-27dece8c2198,f1c4fabb-1dd3-4ffb-b314-0c16bfa97cab
        // now i want to know if there's a uuid of permission in that role, if yes, redirect to the original url

//         const permission = JSON.parse(role.permission);
//         //   console.log(permission);
//         if(!permission){
//             return res.status(404).send({ message: "Unauthorized." });
            
//             // if(req.originalUrl)
//         }
//         const url = Feature.findOne({
//             where:{
//             url: req.originalUrl
//             },
//         })
//         .then(feature => {
//             console.log(feature);
//             if (!feature) {
//             return res.status(404).send({ message: "Unauthorized." });
//             }
//             next();
//             return;
//         })
//       // console.log(permissionObject);
      
//     })
//   })
//   // Role.findOne()
// };

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