require('dotenv').config();

const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const { autenticar, autorizar } = require('./auth');
const {
  ehAdmin,
  somenteProprioUsuario,
  possuiReserva,
  somentePropriaReserva,
  validarCriacaoReserva,
  validarCriacaoEndereco,
  somenteProprioEndereco,
  validarCriacaoPagamento,
  validarCriacaoAgendamento,
  validarConsultaAgendamentos,
  somenteProprioAgendamento
} = require('./autorizacao');

const app = express();
const port = process.env.PORT || 3005;

app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'hotelaria-api-gateway'
  });
});

// Validacao de autenticacao
app.get('/auth/verificar', autenticar, (req, res) => {
  res.json({
    autenticado: true,
    usuarioId: req.usuario.sub,
    roles: req.usuario.roles
  });
});

// Validacao de permissao administrativa
app.get('/admin/verificar', autenticar, autorizar('ADMIN'), (req, res) => {
  res.json({
    autorizado: true
  });
});

// Autorizacao das rotas de Quartos

function liberarProxyQuartos(req, res, next) {
  req.quartoAutorizado = true;
  next();
}

function validarIdNumerico(req, res, next) {
  const ids = Object.values(req.params);

  if (!ids.every(id => /^[1-9]\d*$/.test(id))) {
    return res.status(404).json({
      message: 'Rota ou identificador invalido.'
    });
  }

  next();
}

// Quartos

app.get('/quartos',
  liberarProxyQuartos
);

app.get('/quartos/:id',
  validarIdNumerico,
  liberarProxyQuartos
);

app.post('/quartos',
  autenticar,
  autorizar('ADMIN'),
  liberarProxyQuartos
);

app.patch('/quartos/:id',
  autenticar,
  autorizar('ADMIN'),
  validarIdNumerico,
  liberarProxyQuartos
);

// Tipos de quarto

app.get('/tipos-quarto',
  liberarProxyQuartos
);

app.get('/tipos-quarto/disponiveis',
  liberarProxyQuartos
);

app.get('/tipos-quarto/:id',
  validarIdNumerico,
  liberarProxyQuartos
);

app.post('/tipos-quarto',
  autenticar,
  autorizar('ADMIN'),
  liberarProxyQuartos
);

app.patch('/tipos-quarto/:id',
  autenticar,
  autorizar('ADMIN'),
  validarIdNumerico,
  liberarProxyQuartos
);

// Fotos

app.get('/tipos-quarto/:id/fotos/:fotoId',
  validarIdNumerico,
  liberarProxyQuartos
);

app.post('/tipos-quarto/:id/fotos',
  autenticar,
  autorizar('ADMIN'),
  validarIdNumerico,
  liberarProxyQuartos
);

app.delete('/tipos-quarto/:id/fotos/:fotoId',
  autenticar,
  autorizar('ADMIN'),
  validarIdNumerico,
  liberarProxyQuartos
);

// Comodidades

app.get('/comodidades',
  liberarProxyQuartos
);

app.get('/comodidades/:id',
  validarIdNumerico,
  liberarProxyQuartos
);

app.post('/comodidades',
  autenticar,
  autorizar('ADMIN'),
  liberarProxyQuartos
);

app.delete('/comodidades/:id',
  autenticar,
  autorizar('ADMIN'),
  validarIdNumerico,
  liberarProxyQuartos
);

// Microsservico de Quartos
app.use(
  createProxyMiddleware({
    pathFilter: (pathname, req) => {
      return req.quartoAutorizado === true;
    },
    target: process.env.QUARTOS_SERVICE_URL,
    changeOrigin: true,
    on: {
      proxyReq: (proxyReq) => {
        proxyReq.removeHeader('x-internal-api-key');
      }
    }
  })
);

// Autorizacao das rotas de Usuarios
function liberarProxyUsuarios(req, res, next) {
  req.usuarioAutorizado = true;
  next();
}

app.post('/usuarios',
  express.json(),
  (req, res, next) => {
    if (!req.is('application/json') || !req.body) {
      return res.status(400).json({
        message: 'Corpo JSON obrigatorio.'
      });
    }

    req.body.status = 'ATIVO';
    next();
  },
  liberarProxyUsuarios
);

app.get('/usuarios',
  autenticar,
  autorizar('ADMIN'),
  liberarProxyUsuarios
);

app.get('/usuarios/cpf/:cpf',
  autenticar,
  autorizar('ADMIN'),
  liberarProxyUsuarios
);

app.get('/usuarios/:id',
  autenticar,
  autorizar('ADMIN', 'HOSPEDE'),
  somenteProprioUsuario,
  liberarProxyUsuarios
);

app.patch('/usuarios/:id/senha',
  autenticar,
  autorizar('ADMIN', 'HOSPEDE'),
  somenteProprioUsuario,
  liberarProxyUsuarios
);

app.put('/usuarios/:id',
  autenticar,
  autorizar('ADMIN'),
  liberarProxyUsuarios
);

app.delete('/usuarios/:id',
  autenticar,
  autorizar('ADMIN'),
  liberarProxyUsuarios
);

app.get('/usuarios/:id/enderecos',
  autenticar,
  autorizar('ADMIN', 'HOSPEDE'),
  somenteProprioUsuario,
  liberarProxyUsuarios
);

// Microsservico de Usuarios
app.use(
  createProxyMiddleware({
    pathFilter: (pathname, req) => {
      return req.usuarioAutorizado === true;
    },
    target: process.env.USUARIOS_SERVICE_URL,
    changeOrigin: true,
    pathRewrite: {
      '^/usuarios': '/api/usuarios'
    },
    on: {
      proxyReq: require('http-proxy-middleware').fixRequestBody
    }
  })
);

// Autenticacao centralizada
app.use(
  createProxyMiddleware({
    pathFilter: '/auth',
    target: process.env.USUARIOS_SERVICE_URL,
    changeOrigin: true,
    pathRewrite: {
      '^/auth': '/api/auth'
    }
  })
);

// Autorizacao das rotas de Enderecos

function liberarProxyEnderecos(req, res, next) {
  req.enderecoAutorizado = true;
  next();
}

app.get('/enderecos',
  autenticar,
  autorizar('ADMIN'),
  liberarProxyEnderecos
);

app.post('/enderecos',
  autenticar,
  autorizar('ADMIN', 'HOSPEDE'),
  express.json(),
  validarCriacaoEndereco,
  liberarProxyEnderecos
);

app.get('/enderecos/:id',
  autenticar,
  autorizar('ADMIN', 'HOSPEDE'),
  somenteProprioEndereco,
  liberarProxyEnderecos
);

app.patch('/enderecos/:id',
  autenticar,
  autorizar('ADMIN', 'HOSPEDE'),
  somenteProprioEndereco,
  liberarProxyEnderecos
);

app.delete('/enderecos/:id',
  autenticar,
  autorizar('ADMIN', 'HOSPEDE'),
  somenteProprioEndereco,
  liberarProxyEnderecos
);

// Microsservico de Enderecos
app.use(
  createProxyMiddleware({
    pathFilter: (pathname, req) => {
      return req.enderecoAutorizado === true;
    },
    target: process.env.USUARIOS_SERVICE_URL,
    changeOrigin: true,
    pathRewrite: {
      '^/enderecos': '/api/enderecos'
    },
    on: {
      proxyReq: require('http-proxy-middleware').fixRequestBody
    }
  })
);

// Autorizacao das rotas de Reservas

function liberarProxyReservas(req, res, next) {
  req.reservaAutorizada = true;
  next();
}

app.post('/reservas',
  autenticar,
  autorizar('ADMIN', 'HOSPEDE'),
  express.json(),
  validarCriacaoReserva,
  liberarProxyReservas
);

app.get('/reservas',
  autenticar,
  autorizar('ADMIN'),
  liberarProxyReservas
);

app.get('/reservas/:id',
  autenticar,
  autorizar('ADMIN', 'HOSPEDE'),
  somentePropriaReserva,
  liberarProxyReservas
);

const acoesPermitidas = [
  'confirmar',
  'cancelar',
  'checkin',
  'checkout',
  'finalizar'
];

app.patch('/reservas/:id/:acao',
  autenticar,
  autorizar('ADMIN'),
  (req, res, next) => {
    if (!acoesPermitidas.includes(req.params.acao)) {
      return res.status(404).json({
        message: 'Operacao nao disponibilizada.'
      });
    }

    if (!process.env.INTERNAL_API_KEY) {
      return res.status(503).json({
        message: 'Chave interna nao configurada.'
      });
    }

    req.operacaoInternaAutorizada = true;
    liberarProxyReservas(req, res, next);
  }
);

// Microsservico de Reservas
app.use(
  createProxyMiddleware({
    pathFilter: (pathname, req) => {
      return req.reservaAutorizada === true;
    },
    target: process.env.RESERVAS_SERVICE_URL,
    changeOrigin: true,
    on: {
      proxyReq: (proxyReq, req, res) => {
        proxyReq.removeHeader('x-internal-api-key');

        if (req.operacaoInternaAutorizada === true) {
          proxyReq.setHeader(
            'x-internal-api-key',
            process.env.INTERNAL_API_KEY
          );
        }

        require('http-proxy-middleware')
          .fixRequestBody(proxyReq, req, res);
      }
    }
  })
);

// Catalogo de servicos

app.get('/extras/servicos',
  autenticar,
  autorizar('ADMIN', 'HOSPEDE'),
  liberarProxyExtras
);

app.get('/extras/servicos/:id',
  autenticar,
  autorizar('ADMIN', 'HOSPEDE'),
  liberarProxyExtras
);

app.post('/extras/servicos',
  autenticar,
  autorizar('ADMIN'),
  liberarProxyExtras
);

app.put('/extras/servicos/:id',
  autenticar,
  autorizar('ADMIN'),
  liberarProxyExtras
);

app.patch('/extras/servicos/:id/preco',
  autenticar,
  autorizar('ADMIN'),
  liberarProxyExtras
);

app.patch('/extras/servicos/:id/situacao',
  autenticar,
  autorizar('ADMIN'),
  liberarProxyExtras
);

// Disponibilidades

app.get('/extras/servicos/:servicoId/disponibilidades',
  autenticar,
  autorizar('ADMIN', 'HOSPEDE'),
  liberarProxyExtras
);

app.post('/extras/servicos/:servicoId/verificar-disponibilidade',
  autenticar,
  autorizar('ADMIN', 'HOSPEDE'),
  liberarProxyExtras
);

app.post('/extras/servicos/:servicoId/disponibilidades',
  autenticar,
  autorizar('ADMIN'),
  liberarProxyExtras
);

app.put('/extras/disponibilidades/:id',
  autenticar,
  autorizar('ADMIN'),
  liberarProxyExtras
);

app.delete('/extras/disponibilidades/:id',
  autenticar,
  autorizar('ADMIN'),
  liberarProxyExtras
);

// Agendamentos

app.post('/extras/agendamentos',
  autenticar,
  autorizar('ADMIN', 'HOSPEDE'),
  express.json(),
  validarCriacaoAgendamento,
  liberarProxyExtras
);

app.get('/extras/agendamentos',
  autenticar,
  autorizar('ADMIN', 'HOSPEDE'),
  validarConsultaAgendamentos,
  liberarProxyExtras
);

app.get('/extras/agendamentos/:id',
  autenticar,
  autorizar('ADMIN', 'HOSPEDE'),
  somenteProprioAgendamento,
  liberarProxyExtras
);

app.put('/extras/agendamentos/:id',
  autenticar,
  autorizar('ADMIN', 'HOSPEDE'),
  somenteProprioAgendamento,
  liberarProxyExtras
);

app.patch('/extras/agendamentos/:id/cancelar',
  autenticar,
  autorizar('ADMIN', 'HOSPEDE'),
  somenteProprioAgendamento,
  liberarProxyExtras
);

app.patch('/extras/agendamentos/:id/confirmar',
  autenticar,
  autorizar('ADMIN'),
  liberarProxyExtras
);

app.patch('/extras/agendamentos/:id/concluir',
  autenticar,
  autorizar('ADMIN'),
  liberarProxyExtras
);

// Microsservico de Servicos Extras
app.use(
  createProxyMiddleware({
    pathFilter: (pathname, req) => {
      return req.extrasAutorizado === true;
    },
    target: process.env.EXTRAS_SERVICE_URL,
    changeOrigin: true,
    pathRewrite: {
      '^/extras': '/api/v1'
    },
    on: {
      proxyReq: require('http-proxy-middleware').fixRequestBody
    }
  })
);

// Autorizacao das rotas de Pagamentos

function liberarProxyPagamentos(req, res, next) {
  req.pagamentoAutorizado = true;
  next();
}

app.get('/pagamentos',
  autenticar,
  autorizar('ADMIN'),
  liberarProxyPagamentos
);

app.get('/pagamentos/reserva/:id',
  autenticar,
  autorizar('ADMIN', 'HOSPEDE'),
  somentePropriaReserva,
  liberarProxyPagamentos
);

app.post('/pagamentos',
  autenticar,
  autorizar('ADMIN', 'HOSPEDE'),
  express.json(),
  validarCriacaoPagamento,
  liberarProxyPagamentos
);

app.patch('/pagamentos/:id/:acao',
  autenticar,
  autorizar('ADMIN'),
  (req, res, next) => {
    const acoes = ['aprovar', 'cancelar', 'estornar'];

    if (!acoes.includes(req.params.acao)) {
      return res.status(404).json({
        message: 'Operacao nao disponibilizada.'
      });
    }

    liberarProxyPagamentos(req, res, next);
  }
);

// Microsservico de Pagamentos
app.use(
  createProxyMiddleware({
    pathFilter: (pathname, req) => {
      return req.pagamentoAutorizado === true;
    },
    target: process.env.PAGAMENTOS_SERVICE_URL,
    changeOrigin: true,
    on: {
      proxyReq: require('http-proxy-middleware').fixRequestBody
    }
  })
);

app.listen(port, '127.0.0.1', () => {
  console.log(`API Gateway rodando na porta ${port}`);
});