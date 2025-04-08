import express from 'express';
import { 
    registerCtrl, 
    loginCtrl, 
    refreshTokenCtrl, 
    logoutCtrl,
    googleAuthCtrl, 
    googleAuthCallback 
} from "../auth/auth_controller.js";
import { checkJwt } from '../../middleware/session.js';

const router = express.Router();

/**
 * @swagger
 * components:
 *   schemas:
 *     AuthRegister:
 *       type: object
 *       required:
 *         - name
 *         - password
 *         - email
 *       properties:
 *         name:
 *           type: string
 *           description: El nombre completo del usuario
 *         password:
 *           type: string
 *           description: La contraseña del usuario
 *         age:
 *           type: integer
 *           description: La edad del usuario
 *           default: 0
 *         email:
 *           type: string
 *           description: El correo electrónico del usuario
 *       example:
 *         name: Usuario Ejemplo
 *         password: contraseña123
 *         age: 30
 *         email: usuario@example.com
 *     AuthLogin:
 *       type: object
 *       required:
 *         - email
 *         - password
 *       properties:
 *         email:
 *           type: string
 *           description: El email del usuario
 *         password:
 *           type: string
 *           description: La contraseña del usuario
 *       example:
 *         email: usuario@ejemplo.com
 *         password: contraseña123
 *     RefreshToken:
 *       type: object
 *       required:
 *         - refreshToken
 *       properties:
 *         refreshToken:
 *           type: string
 *           description: El token de refresco
 *       example:
 *         refreshToken: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 */

/**
 * @swagger
 * /api/auth/register:
 *   post:
 *     summary: Registra un nuevo usuario
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/AuthRegister'
 *     responses:
 *       200:
 *         description: Usuario registrado exitosamente
 *       400:
 *         description: Error en la solicitud
 */
router.post("/auth/register", registerCtrl);

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Inicia sesión un usuario
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/AuthLogin'
 *     responses:
 *       200:
 *         description: Inicio de sesión exitoso
 *       400:
 *         description: Error en la solicitud
 */
router.post("/auth/login", loginCtrl);

/**
 * @swagger
 * /api/auth/refresh:
 *   post:
 *     summary: Refresca el token de acceso
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/RefreshToken'
 *     responses:
 *       200:
 *         description: Token refrescado exitosamente
 *       401:
 *         description: Token de refresco inválido
 */
router.post("/auth/refresh", refreshTokenCtrl);

/**
 * @swagger
 * /api/auth/logout:
 *   post:
 *     summary: Cierra la sesión del usuario
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Sesión cerrada exitosamente
 *       401:
 *         description: No autorizado
 */
router.post("/auth/logout", checkJwt, logoutCtrl);

/**
 * @swagger
 * /api/auth/google:
 *   get:
 *     summary: Redirige al usuario a Google para autenticarse
 *     tags: [Auth]
 *     responses:
 *       302:
 *         description: Redirección a Google para autenticación
 */
router.get('/auth/google', googleAuthCtrl);

/**
 * @swagger
 * /api/auth/google/callback:
 *   get:
 *     summary: Callback de Google OAuth
 *     tags: [Auth]
 *     responses:
 *       200:
 *         description: Autenticación exitosa, redirige al frontend con el token
 *       400:
 *         description: Error en la autenticación
 */
router.get('/auth/google/callback', googleAuthCallback);

export default router;