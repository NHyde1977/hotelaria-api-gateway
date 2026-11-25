function ehAdmin(req) {
  return req.usuario?.roles?.includes('ADMIN') === true;
}

function somenteProprioUsuario(req, res, next) {
  if (ehAdmin(req) || req.usuario?.sub === req.params.id) {
    return next();
  }

  return res.status(403).json({
    message: 'Acesso aos dados de outro usuario nao permitido.'
  });
}

async function possuiReserva(req, reservaId) {
  if (ehAdmin(req)) {
    return true;
  }

  const response = await fetch(
    `${process.env.RESERVAS_SERVICE_URL}/reservas/${encodeURIComponent(reservaId)}`,
    { signal: AbortSignal.timeout(5000) }
  );

  if (response.status === 404) {
    return false;
  }

  if (!response.ok) {
    throw new Error('Falha ao consultar reserva.');
  }

  const reserva = await response.json();

  return reserva.hospede_reserva?.some(
    hospede =>
      hospede.usuario_id === req.usuario?.sub &&
      hospede.tipo === 'TITULAR'
  ) === true;
}

async function somentePropriaReserva(req, res, next) {
  try {
    if (await possuiReserva(req, req.params.id)) {
      return next();
    }

    return res.status(403).json({
      message: 'Acesso a reserva nao permitido.'
    });
  } catch {
    return res.status(503).json({
      message: 'Nao foi possivel validar a titularidade da reserva.'
    });
  }
}

function validarCriacaoReserva(req, res, next) {
  if (ehAdmin(req)) {
    return next();
  }

  const hospedes = req.body?.hospedes;

  if (!Array.isArray(hospedes)) {
    return res.status(400).json({
      message: 'Lista de hospedes invalida.'
    });
  }

  const titulares = hospedes.filter(
    hospede => hospede?.tipo === 'TITULAR'
  );

  if (
    titulares.length !== 1 ||
    titulares[0].usuarioId !== req.usuario?.sub
  ) {
    return res.status(403).json({
      message: 'O usuario autenticado deve ser o titular da reserva.'
    });
  }

  return next();
}

function validarCriacaoEndereco(req, res, next) {
  if (ehAdmin(req) || req.body?.usuario_id === req.usuario?.sub) {
    return next();
  }

  return res.status(403).json({
    message: 'Cadastro de endereco para outro usuario nao permitido.'
  });
}

async function somenteProprioEndereco(req, res, next) {
  if (ehAdmin(req)) {
    return next();
  }

  try {
    const response = await fetch(
      `${process.env.USUARIOS_SERVICE_URL}/api/enderecos/${encodeURIComponent(req.params.id)}`,
      { signal: AbortSignal.timeout(5000) }
    );

    if (response.status === 404) {
      return res.status(404).json({
        message: 'Endereco nao encontrado.'
      });
    }

    if (!response.ok) {
      throw new Error('Falha ao consultar endereco.');
    }

    const endereco = await response.json();

    if (endereco.usuario_id !== req.usuario?.sub) {
      return res.status(403).json({
        message: 'Acesso ao endereco nao permitido.'
      });
    }

    return next();
  } catch {
    return res.status(503).json({
      message: 'Nao foi possivel validar a titularidade do endereco.'
    });
  }
}

async function validarCriacaoPagamento(req, res, next) {
  const reservaId = req.body?.reserva_id;

  if (typeof reservaId !== 'string' || !reservaId) {
    return res.status(400).json({
      message: 'Identificador da reserva invalido.'
    });
  }

  try {
    if (await possuiReserva(req, reservaId)) {
      return next();
    }

    return res.status(403).json({
      message: 'Pagamento de reserva de outro usuario nao permitido.'
    });
  } catch {
    return res.status(503).json({
      message: 'Nao foi possivel validar a titularidade da reserva.'
    });
  }
}

async function validarCriacaoAgendamento(req, res, next) {
  const reservaId = req.body?.reservaId;

  if (typeof reservaId !== 'string' || !reservaId) {
    return res.status(400).json({
      message: 'Identificador da reserva invalido.'
    });
  }

  try {
    if (await possuiReserva(req, reservaId)) {
      return next();
    }

    return res.status(403).json({
      message: 'Agendamento para reserva de outro usuario nao permitido.'
    });
  } catch {
    return res.status(503).json({
      message: 'Nao foi possivel validar a titularidade da reserva.'
    });
  }
}

async function validarConsultaAgendamentos(req, res, next) {
  if (ehAdmin(req)) {
    return next();
  }

  const reservaId = req.query.reservaId;

  if (typeof reservaId !== 'string' || !reservaId) {
    return res.status(400).json({
      message: 'Informe o identificador da reserva.'
    });
  }

  try {
    if (await possuiReserva(req, reservaId)) {
      return next();
    }

    return res.status(403).json({
      message: 'Acesso aos agendamentos nao permitido.'
    });
  } catch {
    return res.status(503).json({
      message: 'Nao foi possivel validar a titularidade da reserva.'
    });
  }
}

async function somenteProprioAgendamento(req, res, next) {
  if (ehAdmin(req)) {
    return next();
  }

  try {
    const response = await fetch(
      `${process.env.EXTRAS_SERVICE_URL}/api/v1/agendamentos/${encodeURIComponent(req.params.id)}`,
      {
        headers: {
          Authorization: req.headers.authorization
        },
        signal: AbortSignal.timeout(5000)
      }
    );

    if (response.status === 404) {
      return res.status(404).json({
        message: 'Agendamento nao encontrado.'
      });
    }

    if (!response.ok) {
      throw new Error('Falha ao consultar agendamento.');
    }

    const agendamento = await response.json();

    if (typeof agendamento.reservaId !== 'string') {
      throw new Error('Identificador da reserva indisponivel.');
    }

    if (await possuiReserva(req, agendamento.reservaId)) {
      return next();
    }

    return res.status(403).json({
      message: 'Acesso ao agendamento nao permitido.'
    });
  } catch {
    return res.status(503).json({
      message: 'Nao foi possivel validar a titularidade do agendamento.'
    });
  }
}

module.exports = {
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
};