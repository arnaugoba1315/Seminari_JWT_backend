import { Request, Response, NextFunction } from "express";
import { verifyToken, verifyRefreshToken, generateToken } from "../utils/jwt.handle.js";
import { JwtPayload } from "jsonwebtoken";
import User from "../modules/users/user_models.js";

interface RequestExt extends Request {
    user?: string | JwtPayload;
}

const checkJwt = async (req: RequestExt, res: Response, next: NextFunction) => {
    try {
        const jwtByUser = req.headers.authorization || null;
        const jwt = jwtByUser?.split(' ').pop(); // ['Bearer', '11111'] -> ['11111']
        
        if (!jwt) {
            return res.status(401).send("NO_TOKEN_PROVIDED");
        }
        
        const isUser = verifyToken(`${jwt}`);
        
        if (!isUser) {
            // Intentamos refrescar el token automáticamente si hay un refresh token
            const refreshToken = req.cookies?.refreshToken;
            
            if (!refreshToken) {
                return res.status(401).send("TOKEN_EXPIRED_NO_REFRESH");
            }
            
            // Verificamos el refresh token
            const refreshPayload = verifyRefreshToken(refreshToken);
            if (!refreshPayload) {
                return res.status(401).send("INVALID_REFRESH_TOKEN");
            }
            
            // Buscamos al usuario para verificar que el refresh token es válido
            const email = (refreshPayload as any).id;
            const user = await User.findOne({ email });
            
            if (!user || user.refreshToken !== refreshToken) {
                return res.status(401).send("INVALID_REFRESH_TOKEN");
            }
            
            // Generamos un nuevo token de acceso
            const newToken = generateToken(user.email, user.role, user.name);
            
            // Asignamos el usuario al request para que esté disponible en los controladores
            req.user = { id: user.email, role: user.role, name: user.name };
            
            // Establecemos el nuevo token en la respuesta
            res.setHeader('Authorization', `Bearer ${newToken}`);
            
            // Continuamos con la ejecución
            return next();
        }
        
        // Si el token es válido, asignamos el usuario al request
        req.user = isUser;
        next();
    } catch (e) {
        console.error("Error en checkJwt:", e);
        return res.status(401).send("SESSION_NO_VALID");
    }
};

// Middleware para verificar roles
const checkRole = (roles: string[]) => {
    return (req: RequestExt, res: Response, next: NextFunction) => {
        // El usuario ya debe estar autenticado
        const userRole = (req.user as any)?.role || 'user';
        
        if (!roles.includes(userRole)) {
            return res.status(403).json({ message: 'No tienes permiso para acceder a este recurso' });
        }
        
        next();
    };
};

export { checkJwt, checkRole };