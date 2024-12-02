require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const socketIo = require('socket.io');

// Crear una instancia de la aplicación Express
const app = express();
const port = process.env.PORT || 3000;

// Configurar CORS para permitir solo solicitudes desde un dominio específico
const corsOptions = {
  origin: 'http://192.168.1.119:4200',
  methods: ['GET', 'POST', 'PUT'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
};

app.use(cors(corsOptions));

// Middleware para parsear JSON en las peticiones POST
app.use(express.json());
app.use(cookieParser());

// Configurar la conexión con la base de datos MySQL
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

// Conectar a la base de datos MySQL
db.connect((err) => {
  if (err) {
    console.error('Error al conectar a la base de datos:', err);
  } else {
    console.log('Conectado a la base de datos');
  }
});

// Ruta de login
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'El nombre de usuario y la contraseña son requeridos' });
  }

  const query = 'SELECT id, username, role, password, de_nombres, de_apellidos FROM users WHERE username = ?';
  db.query(query, [username], (err, results) => {
    if (err) {
      console.error('Error en la consulta:', err);
      return res.status(500).json({ error: 'Error en el servidor' });
    }
    if (results.length > 0) {
      const user = results[0];
      if (password !== user.password) {
        return res.status(401).json({ error: 'Nombre de usuario o contraseña incorrectos' });
      }
      const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
      res.status(200).json({
        success: true,
        message: 'Login exitoso',
        token: token,
        user: {
          id: user.id,
          username: user.username,
          role: user.role,
          de_nombres: user.de_nombres,
          de_apellidos: user.de_apellidos
        }
      });
    } else {
      return res.status(401).json({ error: 'Nombre de usuario o contraseña incorrectos' });
    }
  });
});

// Middleware para verificar el token JWT
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1]; // Obtener el token sin el prefijo 'Bearer'
  if (!token) {
    return res.status(401).json({ error: 'Token no proporcionado' });
  }
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Token no válido' });
    }
    req.user = decoded; // Almacena los datos del usuario en la solicitud
    next();
  });
};

app.get('/api/pedidos/user', verifyToken, (req, res) => {
  const userId = req.user.id;
  const role = req.user.role;
  console.log("ROL: ", role);
  // Consulta dinámica según el rol
  const query = role === 'ADMIN'
    ? `
      SELECT p.*, u.de_nombres, u.de_apellidos, e.nombre AS empresa_nombre, e.logo 
      FROM pedidos p
      JOIN users u ON p.id_user = u.id
      JOIN usuario_empresa ue ON ue.usuario_id = u.id
      JOIN empresa e ON ue.empresa_id = e.id
    `
    : `
      SELECT p.*, u.de_nombres, u.de_apellidos, e.nombre AS empresa_nombre, e.logo 
      FROM pedidos p
      JOIN users u ON p.id_user = u.id
      JOIN usuario_empresa ue ON ue.usuario_id = u.id
      JOIN empresa e ON ue.empresa_id = e.id
      WHERE p.id_user = ?
    `;
  const params = role === 'ADMIN' ? [] : [userId];
  db.query(query, params, (error, results) => {
    if (error) {
      console.error('Error al obtener los pedidos:', error);
      return res.status(500).json({ error: 'Error al obtener los pedidos' });
    }
    if (results.length === 0) {
      return res.status(404).json({ message: 'No se encontraron pedidos' });
    }
    // Estructurar datos por empresa
    const groupedData = results.reduce((acc, pedido) => {
      const { empresa_nombre, logo, de_apellidos, de_nombres, ...pedidoData } = pedido;

      if (!acc[empresa_nombre]) {
        acc[empresa_nombre] = {
          logo,
          usuarios: {},
        };
      }
      const usuarioFullName = `${de_apellidos} ${de_nombres}`;
      if (!acc[empresa_nombre].usuarios[usuarioFullName]) {
        acc[empresa_nombre].usuarios[usuarioFullName] = [];
      }
      acc[empresa_nombre].usuarios[usuarioFullName].push(pedidoData);
      return acc;
    }, {});
    res.status(200).json({ empresas: groupedData });
  });
});

// Ruta para crear un nuevo pedido (solo si está autenticado)
app.post('/api/pedidos', verifyToken, (req, res) => {
  const { det_pedido } = req.body;
  const userId = req.user.id;

  if (!det_pedido) {
    return res.status(400).json({ error: 'El detalle del pedido es obligatorio' });
  }

  // Obtener el máximo código de pedido
  db.query(
    'SELECT MAX(CAST(SUBSTRING(cod_pedido, 6) AS UNSIGNED)) AS maxCod FROM pedidos WHERE id_user = ?',
    [userId],
    (error, results) => {
      if (error) {
        console.error('Error al obtener el último código de pedido:', error);
        return res.status(500).json({ error: 'Error al obtener el último código de pedido' });
      }

      const maxCod = results[0]?.maxCod || 0;
      const nuevoCod = `PED-${String(maxCod + 1).padStart(5, '0')}`;

      // Obtener el máximo número de id_room
      db.query(
        'SELECT MAX(CAST(SUBSTRING(id_room, 5) AS UNSIGNED)) AS maxRoom FROM pedidos',
        (roomError, roomResults) => {
          if (roomError) {
            console.error('Error al obtener el último id_room:', roomError);
            return res.status(500).json({ error: 'Error al obtener el último id_room' });
          }

          const maxRoom = roomResults[0]?.maxRoom || 0;
          const nuevoRoom = `room${maxRoom + 1}`;

          // Insertar el nuevo pedido con id_room
          db.query(
            'INSERT INTO pedidos (id, cod_pedido, det_pedido, id_user, est_pedido, id_room) VALUES (UUID(), ?, ?, ?, ?, ?)',
            [nuevoCod, det_pedido, userId, 'PENDIENTE', nuevoRoom],
            (insertError) => {
              if (insertError) {
                console.error('Error al insertar el pedido:', insertError);
                return res.status(500).json({ error: 'Error al crear el pedido' });
              }

              res.status(201).json({
                message: 'Pedido creado exitosamente',
                cod_pedido: nuevoCod,
                id_room: nuevoRoom,
              });
            }
          );
        }
      );
    }
  );
});

app.get('/api/messages/:roomId', verifyToken, (req, res) => {
  const roomId = req.params.roomId;
  const query = `
    SELECT
      m.id as messageId,
      m.message, 
      m.userId, 
      DATE_FORMAT(m.timestamp, '%Y-%m-%d %H:%i:%s') AS timestamp, 
      u.de_nombres AS nombres, 
      u.de_apellidos AS apellidos
    FROM messages m
    JOIN users u ON m.userId = u.id
    WHERE m.roomId = ? AND m.estado = 'A'
    ORDER BY m.timestamp ASC
  `;
  db.query(query, [roomId], (error, results) => {
    if (error) {
      console.error('Error al obtener los mensajes:', error);
      return res.status(500).json({ error: 'Error al obtener los mensajes' });
    }
    if (results.length === 0) {
      return res.status(404).json({ message: 'No se encontraron mensajes para este roomId' });
    }
    res.status(200).json({ messages: results });
  });
});

app.post('/api/sendMessage', verifyToken, (req, res) => {
  const { roomId, message, userId, timestamp, nombres, apellidos, estado } = req.body;
  // Validar los parámetros
  if (!roomId || !message || !userId || !timestamp || !nombres || !apellidos || !estado) {
    return res.status(400).json({ error: 'Faltan parámetros' });
  }
  // Validar el formato de la fecha
  const isValidTimestamp = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(timestamp);
  if (!isValidTimestamp) {
    return res.status(400).json({ error: 'Formato de fecha no válido. Debe ser YYYY-MM-DD HH:mm:ss' });
  }
  // Insertar el mensaje en la base de datos, incluyendo los nombres y apellidos
  db.query(
    'INSERT INTO messages (roomId, message, timestamp, userId, nombres, apellidos, estado) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [roomId, message, timestamp, userId, nombres, apellidos, estado],
    (insertError, result) => {
      if (insertError) {
        console.error('Error al insertar el mensaje:', insertError);
        return res.status(500).json({ error: 'Error al guardar el mensaje' });
      }
      // Emitir el mensaje a todos los clientes conectados en la sala, incluyendo los nombres y apellidos
      io.emit('newMessage', { roomId, message, userId, timestamp, nombres, apellidos, estado });
      // Responder con el mensaje guardado
      res.status(200).json({ success: true, message: 'Mensaje enviado correctamente' });
    }
  );
});

app.put('/api/updateMessageStatus/:messageId', verifyToken, (req, res) => {
  const { messageId } = req.params;
  const { estado } = req.body;
  // Validar parámetros
  if (!messageId || !estado) {
    return res.status(400).json({ error: 'Faltan parámetros' });
  }
  // Actualizar el estado del mensaje en la base de datos
  db.query(
    'UPDATE messages SET estado = ? WHERE id = ?',
    [estado, messageId],
    (updateError, result) => {
      if (updateError) {
        console.error('Error al actualizar el estado del mensaje:', updateError);
        return res.status(500).json({ error: 'Error al actualizar el estado del mensaje' });
      }
      // Emitir el evento de mensaje actualizado a los clientes conectados
      io.emit('messageUpdated', { messageId, estado });
      res.status(200).json({ success: true, message: 'Estado del mensaje actualizado' });
    }
  );
});

// Ruta para obtener la cantidad de mensajes nuevos para un usuario
app.get('/api/unreadMessages/:userId', verifyToken, (req, res) => {
  const userId = parseInt(req.params.userId, 10);

  if (isNaN(userId)) {
    return res.status(400).json({ error: 'ID de usuario no válido' });
  }

  const query = `
    SELECT COUNT(*) AS newMessagesCount
    FROM messages
    WHERE roomId IN (
      SELECT id_room
      FROM pedidos
      WHERE id_user = ?
    ) AND confirmacion = 'N';
  `;

  db.query(query, [userId], (error, results) => {
    if (error) {
      console.error('Error al consultar mensajes no leídos:', error);
      return res.status(500).json({ error: 'Error al consultar mensajes' });
    }

    res.status(200).json({ newMessagesCount: results[0]?.newMessagesCount || 0 });
  });
});

app.put('/api/messages/markAsRead', verifyToken, (req, res) => {
  const { roomId, userId } = req.body;

  if (!roomId || !userId) {
    return res.status(400).json({ error: 'Parámetros faltantes' });
  }

  const query = `
    UPDATE messages
    SET confirmacion = 'L'
    WHERE roomId = ? AND userId != ? AND confirmacion = 'N';
  `;

  db.query(query, [roomId, userId], (error) => {
    if (error) {
      console.error('Error al marcar mensajes como leídos:', error);
      return res.status(500).json({ error: 'Error al actualizar mensajes' });
    }

    res.status(200).json({ success: true });
  });
});

const multer = require('multer');
const path = require('path');

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = path.join(__dirname, 'uploads'); 
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    const timestamp = Date.now();
    cb(null, `${timestamp}-${file.originalname}`);
  },
});

const upload = multer({ storage });

// Endpoint para cargar un documento vinculado a un id_pedido
app.post('/api/uploadDocument', verifyToken, upload.single('file'), (req, res) => {
  const { file } = req; 
  const { id_pedido } = req.body;
  if (!file || !id_pedido) {
    return res.status(400).json({ error: 'Archivo o id_pedido no proporcionado' });
  }
  const query = `
    INSERT INTO documentos (nombre, id_pedido)
    VALUES (?, ?)
  `;
  db.query(query, [file.filename, id_pedido], (error) => {
    if (error) {
      console.error('Error al guardar el documento:', error);
      return res.status(500).json({ error: 'Error al guardar el documento en la base de datos' });
    }
    res.status(200).json({ 
      message: 'Documento cargado exitosamente', 
      fileName: file.filename 
    });
  });
});

// Ruta para obtener los documentos asociados a un id_pedido
app.get('/api/documents/:id_pedido', verifyToken, (req, res) => {
  const { id_pedido } = req.params;
  if (!id_pedido) {
    return res.status(400).json({ error: 'id_pedido no proporcionado' });
  }
  // Consulta para obtener los documentos vinculados al id_pedido
  const query = `
    SELECT id, nombre, id_pedido
    FROM documentos
    WHERE id_pedido = ?
  `;
  db.query(query, [id_pedido], (error, results) => {
    if (error) {
      console.error('Error al obtener los documentos:', error);
      return res.status(500).json({ error: 'Error al obtener los documentos' });
    }
    // Si no hay documentos, devolver un array vacío
    res.status(200).json(results);
  });
});

// Configuración de Socket.IO
const server = app.listen(port, () => {
  console.log(`Servidor escuchando en http://192.168.1.119:${port}`);
});

const io = socketIo(server);

const connectedUsers = {};

io.on('connection', (socket) => {
  console.log('Nuevo cliente conectado:', socket.id);

  /**
   * Función para emitir la lista actualizada de usuarios conectados en una sala.
   * @param {string} roomId
   */
  const emitUpdatedUsers = (roomId) => {
    if (!connectedUsers[roomId] || connectedUsers[roomId].length === 0) {
      delete connectedUsers[roomId];
    }
    console.log(`Usuarios conectados en la sala ${roomId}:`, connectedUsers[roomId]);
    io.to(roomId).emit('updateUsers', connectedUsers[roomId] || []);
  };  

  socket.on('joinRoom', async ({ roomId, userId, nombres, apellidos, role }) => {
    console.log('Datos recibidos en joinRoom:', { roomId, userId, nombres, apellidos, role });
    
    if (!roomId || !userId || !nombres || !apellidos || !role) {
      console.error('Faltan datos para unirse a la sala:', { roomId, userId, nombres, apellidos, role });
      socket.emit('errorEvent', { error: 'Datos incompletos para unirse a la sala' });
      return;
    }

    socket.join(roomId);
    console.log(`Usuario ${nombres} ${apellidos} (ID: ${userId}, Rol: ${role}) se unió a la sala ${roomId}`);

    connectedUsers[roomId] = connectedUsers[roomId] || [];
    const user = { userId, nombres, apellidos, socketId: socket.id, role };
    connectedUsers[roomId].push(user);

    emitUpdatedUsers(roomId);
  });  

  socket.on('send_message', async (data) => {
    console.log('Mensaje recibido:', data);
    console.log("Room Id: ",data.roomId);
    // Validar datos antes de emitir
    if (!data.message || !data.userId || !data.roomId || !data.timestamp) {
      console.error('Datos incompletos recibidos desde el cliente:', data);
      socket.emit('errorEvent', { error: 'Datos incompletos para enviar mensaje' });
      return;
    }

    // Verificar roles conectados en la sala
    const usersInRoom = connectedUsers[data.roomId] || [];
    const hasUser = usersInRoom.some(user => user.role === 'USER');
    const hasAdmin = usersInRoom.some(user => user.role === 'ADMIN');

    // Lógica para actualizar la tabla notificaciones
    if ((hasUser && !hasAdmin) || (!hasUser && hasAdmin)) {
      const absentRole = hasUser ? 'ADMIN' : 'USER';
      const query = `UPDATE notificaciones SET ${absentRole.toLowerCase()} = 1 WHERE solicitud = ?`;
      await db.query(query, [data.roomId], (err) => {
        if (err) throw err;
        console.log(`Se actualizó la tabla notificaciones para ${absentRole} ausente en la sala ${data.roomId}`);
      });
    }

    // Emitir el mensaje a todos los clientes conectados en la sala
    io.to(data.roomId).emit('receive_message', data);
  });

  // Manejo de desconexión del cliente
  socket.on('disconnect', () => {
    console.log('Cliente desconectado:', socket.id);

    // Buscar y eliminar al usuario desconectado de las salas
    for (const roomId in connectedUsers) {
      connectedUsers[roomId] = connectedUsers[roomId].filter((user) => user.socketId !== socket.id);

      // Emitir lista actualizada de usuarios conectados
      emitUpdatedUsers(roomId);
    }
  });
});