const routerx = require('express-promise-router');
const articuloRouter = require('./articulo');
const usuarioRouter = require('./usuario');
const categoriaRouter = require('./categoria');
const router = routerx();

router.use('/articulo',articuloRouter);
router.use('/usuario',usuarioRouter);
router.use('/categoria',categoriaRouter);

module.exports = router;