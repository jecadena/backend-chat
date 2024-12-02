-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Servidor: 127.0.0.1
-- Tiempo de generación: 25-11-2024 a las 23:18:40
-- Versión del servidor: 10.4.32-MariaDB
-- Versión de PHP: 8.0.30

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Base de datos: `chat`
--

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `messages`
--

CREATE TABLE `messages` (
  `id` int(11) NOT NULL,
  `roomId` varchar(255) NOT NULL,
  `message` text NOT NULL,
  `timestamp` datetime NOT NULL,
  `userId` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Volcado de datos para la tabla `messages`
--

INSERT INTO `messages` (`id`, `roomId`, `message`, `timestamp`, `userId`) VALUES
(175, 'room5', 'Hola que tal', '2024-11-25 16:24:59', 1),
(176, 'room5', 'Bien gracias y tu?', '2024-11-25 16:25:07', 2),
(177, 'room5', 'Avanzando', '2024-11-25 16:46:44', 1),
(178, 'room5', 'ok', '2024-11-25 16:46:57', 2),
(179, 'room5', 'fff', '2024-11-25 16:56:56', 1),
(180, 'room5', 'mensaje', '2024-11-25 16:59:01', 2),
(181, 'room5', 'Prueba de mensaje', '2024-11-25 17:01:51', 1),
(182, 'room5', 'Respuesta de mensaje', '2024-11-25 17:01:58', 2),
(183, 'room5', 'Este es un mensaje bien largo para ver la alineación del texto', '2024-11-25 17:05:35', 2),
(184, 'room5', 'va la respuesta también larga para ve rla alineación verdadera', '2024-11-25 17:05:54', 1);

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `pedidos`
--

CREATE TABLE `pedidos` (
  `id` varchar(10) NOT NULL,
  `cod_pedido` varchar(10) NOT NULL,
  `det_pedido` text NOT NULL,
  `id_user` int(11) NOT NULL,
  `est_pedido` varchar(20) NOT NULL DEFAULT 'PENDIENTE',
  `id_room` varchar(20) NOT NULL,
  `updated_at` datetime DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Volcado de datos para la tabla `pedidos`
--

INSERT INTO `pedidos` (`id`, `cod_pedido`, `det_pedido`, `id_user`, `est_pedido`, `id_room`, `updated_at`) VALUES
('3451f6c3-a', 'PED-00004', 'Cambiar los datos de los pasajeros Félix y Teresa', 2, 'PENDIENTE', 'room5', NULL),
('740d8172-a', 'PED-00001', 'Adjuntar documentos  para el pasajero Carlos Álvarez que viaja a Miami', 3, 'PENDIENTE', 'room6', NULL),
('85052e94-a', 'PED-00003', 'Otro pedido', 2, 'PENDIENTE', 'room4', NULL),
('c22a47c7-a', 'PED-00001', 'Ingreso del primer pedido', 2, 'PENDIENTE', 'room3', NULL),
('ec1b7ee0-a', 'PED-00001', 'Confirmar los pasajes para la fecha 12/09/2025 al 25/01/2025', 3, 'PENDIENTE', 'room1', NULL),
('f983ac8f-a', 'PED-00002', 'Enviar documentación para los pasajeros Luis Rodríguez y María Álvarez', 3, 'PENDIENTE', 'room2', NULL);

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `username` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `role` enum('USER','ADMIN') DEFAULT 'USER',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `de_nombres` varchar(30) NOT NULL,
  `de_apellidos` varchar(40) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Volcado de datos para la tabla `users`
--

INSERT INTO `users` (`id`, `username`, `password`, `role`, `created_at`, `de_nombres`, `de_apellidos`) VALUES
(1, 'admin@admin.com', 'admin', 'ADMIN', '2024-11-20 17:57:27', 'Juan', 'Pérez'),
(2, 'user1@admin.com', 'password1', 'USER', '2024-11-20 19:48:22', 'Ana', 'Gamarra'),
(3, 'user2@admin.com', 'password2', 'USER', '2024-11-20 19:48:22', 'Pedro', 'Sánchez');

--
-- Índices para tablas volcadas
--

--
-- Indices de la tabla `messages`
--
ALTER TABLE `messages`
  ADD PRIMARY KEY (`id`),
  ADD KEY `userId` (`userId`);

--
-- Indices de la tabla `pedidos`
--
ALTER TABLE `pedidos`
  ADD PRIMARY KEY (`id`),
  ADD KEY `id_user` (`id_user`);

--
-- Indices de la tabla `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`);

--
-- AUTO_INCREMENT de las tablas volcadas
--

--
-- AUTO_INCREMENT de la tabla `messages`
--
ALTER TABLE `messages`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=185;

--
-- AUTO_INCREMENT de la tabla `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- Restricciones para tablas volcadas
--

--
-- Filtros para la tabla `messages`
--
ALTER TABLE `messages`
  ADD CONSTRAINT `messages_ibfk_1` FOREIGN KEY (`userId`) REFERENCES `users` (`id`);

--
-- Filtros para la tabla `pedidos`
--
ALTER TABLE `pedidos`
  ADD CONSTRAINT `pedidos_ibfk_1` FOREIGN KEY (`id_user`) REFERENCES `users` (`id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
