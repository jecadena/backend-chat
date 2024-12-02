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
  origin: 'http://192.168.1.105:4200', // Cambia esto por el origen de tu frontend
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'], // Si necesitas permitir headers personalizados
  credentials: true // Si usas cookies o headers de autenticación
};

// Habilitar CORS con las opciones configuradas
app.use(cors(corsOptions));

// Middleware para parsear JSON en las peticiones POST
app.use(express.json());
app.use(cookieParser()); // Agregar el middleware cookie-parser

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

// Ruta para obtener pedidos por usuario (solo si está autenticado)
app.get('/api/pedidos/user', verifyToken, (req, res) => {
  const userId = req.user.id;
  const role = req.user.role;
  console.log("ROL: ", role);

  // Consulta dinámica según el rol
  const query = role === 'ADMIN'
    ? `
      SELECT p.*, u.de_nombres, u.de_apellidos 
      FROM pedidos p 
      JOIN users u ON p.id_user = u.id
    `
    : `
      SELECT p.*, u.de_nombres, u.de_apellidos 
      FROM pedidos p 
      JOIN users u ON p.id_user = u.id
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

    res.status(200).json({ pedidos: results });
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
      m.message, 
      m.userId, 
      DATE_FORMAT(m.timestamp, '%Y-%m-%d %H:%i:%s') AS timestamp, 
      u.de_nombres AS nombres, 
      u.de_apellidos AS apellidos
    FROM messages m
    JOIN users u ON m.userId = u.id
    WHERE m.roomId = ?
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

// Ruta para enviar un mensaje a través de Socket.IO y almacenarlo en la base de datos
app.post('/api/sendMessage', verifyToken, (req, res) => {
  const { roomId, message, userId, timestamp } = req.body;

  // Validar los parámetros
  if (!roomId || !message || !userId || !timestamp) {
    return res.status(400).json({ error: 'Faltan parámetros' });
  }

  // Validar el formato de la fecha
  const isValidTimestamp = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(timestamp);
  if (!isValidTimestamp) {
    return res.status(400).json({ error: 'Formato de fecha no válido. Debe ser YYYY-MM-DD HH:mm:ss' });
  }

  // Insertar el mensaje en la base de datos
  db.query(
    'INSERT INTO messages (roomId, message, timestamp, userId) VALUES (?, ?, ?, ?)',
    [roomId, message, timestamp, userId],
    (insertError, result) => {
      if (insertError) {
        console.error('Error al insertar el mensaje:', insertError);
        return res.status(500).json({ error: 'Error al guardar el mensaje' });
      }

      // Emitir el mensaje a todos los clientes conectados en la sala
      io.emit('newMessage', { message, userId, timestamp });

      // Responder con el mensaje guardado
      res.status(200).json({ success: true, message: 'Mensaje enviado correctamente' });
    }
  );
});

// Ruta para obtener la cantidad de pedidos con mensajes nuevos
app.get('/api/unreadMessages/:userId', verifyToken, (req, res) => {
  const userId = req.params.userId;
  console.log("usuario: ", userId);

  // Validar si el ID es un UUID válido
  if (!/^[\da-f]{8}-[\da-f]{4}-[\da-f]{4}-[\da-f]{4}-[\da-f]{12}$/i.test(userId)) {
    return res.status(400).json({ error: 'ID de usuario no válido' });
  }

  // Consultar los pedidos con mensajes nuevos
  const query = `
    SELECT COUNT(DISTINCT pedidos.id) AS newMessagesCount
    FROM pedidos
    INNER JOIN messages ON pedidos.id_room = messages.roomId
    WHERE messages.timestamp > pedidos.updated_at
  `;

  db.query(query, [], (queryError, data) => {
    if (queryError) {
      console.error('Error al consultar los mensajes nuevos:', queryError);
      return res.status(500).json({ error: 'Error al consultar los mensajes nuevos' });
    }

    const count = data[0]?.newMessagesCount || 0;
    res.status(200).json({ newMessagesCount: count });
  });
});


// Configuración de Socket.IO
const server = app.listen(port, () => {
  console.log(`Servidor escuchando en http://localhost:${port}`);
});

const io = socketIo(server);

// Manejo de conexiones de Socket.IO
io.on('connection', (socket) => {
  console.log('Nuevo cliente conectado');

  // Escuchar los mensajes del cliente
  socket.on('send_message', (data) => {
    console.log('Mensaje recibido:', data);

    // Validar datos antes de emitir
    if (!data.message || !data.userId || !data.roomId || !data.timestamp) {
      console.error('Datos incompletos recibidos desde el cliente:', data);
      return;
    }

    // Emitir el mensaje a todos los clientes conectados
    io.emit('receive_message', data);
  });

  // Manejo de desconexión del cliente
  socket.on('disconnect', () => {
    console.log('Cliente desconectado');
  });
});
