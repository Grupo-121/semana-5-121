const models = require('../models');
var bcrypt = require('bcryptjs');
const token = require('../services/token');
const megaKey = require('../Key/SecretKey');

module.exports = {
    add: async(req, res, next) => {
        try {
            req.body.password = await bcrypt.hash(req.body.password, 8);
            const reg = await models.Usuario.create(req.body);
            res.status(200).json(reg);
        } catch (e) {
            res.status(500).send({
                message: 'Ocurrió un error'
            });
            next(e);
        }
    },
    list: async(req, res, next) => {
        try {
            let valor = req.query.valor;
            const reg = await models.Usuario.findAll();
            res.status(200).json(reg);
        } catch (e) {
            res.status(500).send({
                message: 'Ocurrió un error'
            });
            next(e);
        }
    },
    update: async(req, res, next) => {
        try {
            let pas = req.body.password;
            const reg0 = await models.Usuario.findOne({ where: { id: req.body.id } });
            if (pas != reg0.password) {
                req.body.password = await bcrypt.hash(req.body.password, 8);
            }
            const reg = await models.Usuario.update({ rol: req.body.rol, nombre: req.body.nombre, tipo_documento: req.body.tipo_documento, num_documento: req.body.num_documento, direccion: req.body.direccion, telefono: req.body.telefono, email: req.body.email, password: req.body.password }, { where: { id: req.body.id } });
            res.status(200).json(reg);
        } catch (e) {
            res.status(500).send({
                message: 'Ocurrió un error'
            });
            next(e);
        }
    },
    activate: async(req, res, next) => {
        try {
            const reg = await models.Usuario.update({ estado: 1 }, { where: { id: req.body.id } });
            res.status(200).json(reg);
        } catch (e) {
            res.status(500).send({
                message: 'Ocurrió un error'
            });
            next(e);
        }
    },
    deactivate: async(req, res, next) => {
        try {
            const reg = await models.Usuario.update({ estado: 0 }, { where: { id: req.body.id } });
            res.status(200).json(reg);
        } catch (e) {
            res.status(500).send({
                message: 'Ocurrió un error'
            });
            next(e);
        }
    },
    login: async(req, res, next) => {
        try {
            console.log(req.body.email)
            let user = await models.Usuario.findOne({ where: { email: req.body.email } });
            if (user) {
                let match = await bcrypt.compare(req.body.password, user.password);
                if (match) {
                    console.log(user.rol);
                    let tokenReturn = await token.encode(user.id, user.rol);
                    res.status(200).json({ user, tokenReturn });
                } else {
                    res.status(401).send({
                        message: 'Password Incorrecto'
                    });
                }
            } else {
                res.status(404).send({
                    message: 'No existe el usuario'
                });
            }
        } catch (e) {
            res.status(500).send({
                message: 'Ocurrió un error'
            });
            next(e);
        }
    },
    register: async(req,res,next) => {
        try {
            const prueba = await models.Usuario.findOne({where: {email: req.body.email}});
            if (!prueba){
                console.log('no está');
                req.body.password = bcrypt.hashSync(req.body.password,8);
                const user = await models.Usuario.create(req.body);
                res.status(200).json(user);
            }else {
                console.log(prueba);
                res.status(444).json({
                    error: 'Error, el correo ya se encuentra registrado'
                })
            }
        } catch (error) {
            res.status(500).send({
                message: 'Error->'
            });
            next(error);
        }
    }
}