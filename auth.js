const jwt = require('jsonwebtoken');

function autenticar(req, res, next) {
  const authorization = req.headers.authorization;

  if (!authorization || !authorization.startsWith('Bearer ')) {
    return res.status(401).json({
      message: 'Token de autenticacao ausente.'
    });
  }

  const token = authorization.slice(7);

  try {
    req.usuario = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ['HS256']
    });
  } catch (error) {
    return res.status(401).json({
      message: 'Token invalido ou expirado.'
    });
  }

  return next();
}

function autorizar(...perfisPermitidos) {
  return (req, res, next) => {
    const roles = req.usuario?.roles;

    if (
      !Array.isArray(roles) ||
      !roles.some(role => perfisPermitidos.includes(role))
    ) {
      return res.status(403).json({
        message: 'Usuario sem permissao para esta operacao.'
      });
    }

    return next();
  };
}

module.exports = { autenticar, autorizar };