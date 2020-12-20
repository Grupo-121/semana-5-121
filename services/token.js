var jwt = require('jsonwebtoken');
const models = require('../models');
const megaKey = require('../Key/SecretKey');

const checkToken = async (token) => {
    const _id = null;
    try {
        const { idD } = await jwt.decode(token);
        _id = idD;
    } catch (error) {
        return false
    } 
    const user = await models.Usuario.findOne({ where: {id: _id}});
    if (user) {
        const tok = jwt.sign({ id: user.id},megaKey,{expiresIn:'1d'});
        return { tok ,rol: user.rol };
    } else {
        return false;
    }
}

module.exports = {

    // generar el token
    encode: async(id, rol) => {
        console.log(rol);
        const token = jwt.sign({ id: id, rol: rol },megaKey.key, { expiresIn: '1d' });
        return token;
    },
    // permite decodificar el token y validarlo, en caso de que esté expirado lo renueva
    decode: async(token) => {
        try {
            const { id } = await jwt.verify(token, megaKey.key);
            const user = await models.Usuario.findOne({ where: { id: id } });
            if (user) {
                return user;
            } else {
                return false;
            }
        } catch (e) {
            const tokenNuevo = await checkToken(token);
            return tokenNuevo;
        }

    }
}