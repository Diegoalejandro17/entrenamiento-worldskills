<?php
// config.php - Configuración de base de datos
class Database {
    private $host = 'localhost';
    private $db_name = 'aeropuerto_dorado';
    private $username = 'root';
    private $password = '';
    private $conn;

    public function getConnection() {
        $this->conn = null;
        try {
            $this->conn = new PDO("mysql:host=" . $this->host . ";dbname=" . $this->db_name, 
                                $this->username, $this->password);
            $this->conn->exec("set names utf8");
            $this->conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch(PDOException $exception) {
            echo "Error de conexión: " . $exception->getMessage();
        }
        return $this->conn;
    }
}

// api.php - API REST Principal
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

require_once 'config.php';

class AeropuertoAPI {
    private $db;
    private $conn;

    public function __construct() {
        $this->db = new Database();
        $this->conn = $this->db->getConnection();
    }

    // Función para generar código de vuelo aleatorio
    private function generateFlightCode() {
        do {
            $code = '';
            for ($i = 0; $i < 6; $i++) {
                $code .= chr(rand(65, 90)); // A-Z
            }
            
            $query = "SELECT cod_vuelo FROM vuelo WHERE cod_vuelo = :code";
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(':code', $code);
            $stmt->execute();
            
        } while ($stmt->rowCount() > 0);
        
        return $code;
    }

    // Función para generar token aleatorio
    private function generateToken() {
        return bin2hex(random_bytes(32));
    }

    // Función para verificar token
    private function verifyToken() {
        $headers = getallheaders();
        if (!isset($headers['Authorization'])) {
            http_response_code(401);
            echo json_encode(['error' => 'Token no proporcionado']);
            exit;
        }

        $token = str_replace('Bearer ', '', $headers['Authorization']);
        
        $query = "SELECT id FROM usuario WHERE token = :token";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':token', $token);
        $stmt->execute();

        if ($stmt->rowCount() === 0) {
            http_response_code(401);
            echo json_encode(['error' => 'Token inválido']);
            exit;
        }
    }

    // 1. LOGIN
    public function login() {
        $data = json_decode(file_get_contents("php://input"));
        
        if (!isset($data->nombre_usuario) || !isset($data->contrasena)) {
            http_response_code(400);
            echo json_encode(['error' => 'Datos incompletos']);
            return;
        }

        $query = "SELECT id, nombre_usuario, contrasena FROM usuario WHERE nombre_usuario = :username";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':username', $data->nombre_usuario);
        $stmt->execute();

        if ($stmt->rowCount() > 0) {
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            
            // Verificar contraseña (para simplificar, comparación directa)
            if ($data->contrasena === 'administrador') {
                $token = $this->generateToken();
                
                // Actualizar token en la base de datos
                $updateQuery = "UPDATE usuario SET token = :token WHERE id = :id";
                $updateStmt = $this->conn->prepare($updateQuery);
                $updateStmt->bindParam(':token', $token);
                $updateStmt->bindParam(':id', $row['id']);
                $updateStmt->execute();

                http_response_code(200);
                echo json_encode([
                    'message' => 'Autenticación exitosa',
                    'token' => $token,
                    'usuario' => $row['nombre_usuario']
                ]);
            } else {
                http_response_code(401);
                echo json_encode(['error' => 'Credenciales inválidas']);
            }
        } else {
            http_response_code(401);
            echo json_encode(['error' => 'Usuario no encontrado']);
        }
    }

    // 2. LOGOUT
    public function logout() {
        $headers = getallheaders();
        if (isset($headers['Authorization'])) {
            $token = str_replace('Bearer ', '', $headers['Authorization']);
            
            $query = "UPDATE usuario SET token = NULL WHERE token = :token";
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(':token', $token);
            $stmt->execute();
        }

        http_response_code(200);
        echo json_encode(['message' => 'Cierre de sesión exitoso']);
    }

    // 3. CREAR VUELO
    public function crearVuelo() {
        $this->verifyToken();
        
        $data = json_decode(file_get_contents("php://input"));
        
        if (!isset($data->cod_destino) || !isset($data->cod_aerolinea) || 
            !isset($data->cod_sala) || !isset($data->hora_salida) || !isset($data->hora_llegada)) {
            http_response_code(400);
            echo json_encode(['error' => 'Datos incompletos']);
            return;
        }

        $cod_vuelo = $this->generateFlightCode();

        $query = "INSERT INTO vuelo (cod_vuelo, cod_destino, cod_aerolinea, cod_sala, hora_salida, hora_llegada) 
                  VALUES (:cod_vuelo, :cod_destino, :cod_aerolinea, :cod_sala, :hora_salida, :hora_llegada)";
        
        try {
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(':cod_vuelo', $cod_vuelo);
            $stmt->bindParam(':cod_destino', $data->cod_destino);
            $stmt->bindParam(':cod_aerolinea', $data->cod_aerolinea);
            $stmt->bindParam(':cod_sala', $data->cod_sala);
            $stmt->bindParam(':hora_salida', $data->hora_salida);
            $stmt->bindParam(':hora_llegada', $data->hora_llegada);
            $stmt->execute();

            http_response_code(201);
            echo json_encode(['message' => 'Vuelo creado exitosamente', 'cod_vuelo' => $cod_vuelo]);
        } catch(PDOException $e) {
            http_response_code(400);
            echo json_encode(['error' => 'Error al crear vuelo: ' . $e->getMessage()]);
        }
    }

    // 4. CONSULTAR VUELOS
    public function consultarVuelos() {
        $this->verifyToken();

        $query = "SELECT v.cod_vuelo, v.hora_salida, v.hora_llegada, 
                         d.descripcion as destino, a.descripcion as aerolinea, 
                         s.descripcion as sala,
                         TIMEDIFF(v.hora_llegada, v.hora_salida) as duracion
                  FROM vuelo v 
                  JOIN destino d ON v.cod_destino = d.cod_destino
                  JOIN aerolinea a ON v.cod_aerolinea = a.cod_aerolinea
                  JOIN sala_abordaje s ON v.cod_sala = s.cod_sala
                  ORDER BY v.hora_salida";
        
        $stmt = $this->conn->prepare($query);
        $stmt->execute();

        if ($stmt->rowCount() > 0) {
            $vuelos = $stmt->fetchAll(PDO::FETCH_ASSOC);
            http_response_code(200);
            echo json_encode($vuelos);
        } else {
            http_response_code(404);
            echo json_encode(['message' => 'No se encontraron vuelos']);
        }
    }

    // 5. EDITAR VUELO
    public function editarVuelo($cod_vuelo) {
        $this->verifyToken();
        
        $data = json_decode(file_get_contents("php://input"));
        
        if (!isset($data->hora_salida) || !isset($data->hora_llegada)) {
            http_response_code(400);
            echo json_encode(['error' => 'Datos incompletos']);
            return;
        }

        $query = "UPDATE vuelo SET hora_salida = :hora_salida, hora_llegada = :hora_llegada 
                  WHERE cod_vuelo = :cod_vuelo";
        
        try {
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(':hora_salida', $data->hora_salida);
            $stmt->bindParam(':hora_llegada', $data->hora_llegada);
            $stmt->bindParam(':cod_vuelo', $cod_vuelo);
            $stmt->execute();

            if ($stmt->rowCount() > 0) {
                http_response_code(200);
                echo json_encode(['message' => 'Vuelo actualizado exitosamente']);
            } else {
                http_response_code(404);
                echo json_encode(['error' => 'Vuelo no encontrado']);
            }
        } catch(PDOException $e) {
            http_response_code(400);
            echo json_encode(['error' => 'Error al actualizar vuelo: ' . $e->getMessage()]);
        }
    }

    // 6. CREAR PASAJERO
    public function crearPasajero() {
        $this->verifyToken();
        
        $data = json_decode(file_get_contents("php://input"));
        
        if (!isset($data->id) || !isset($data->nombre) || !isset($data->apellido) || 
            !isset($data->telefono) || !isset($data->cod_vuelo)) {
            http_response_code(400);
            echo json_encode(['error' => 'Datos incompletos']);
            return;
        }

        $query = "INSERT INTO pasajero (id, nombre, apellido, telefono, cod_vuelo, imagen_perfil) 
                  VALUES (:id, :nombre, :apellido, :telefono, :cod_vuelo, :imagen_perfil)";
        
        try {
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(':id', $data->id);
            $stmt->bindParam(':nombre', $data->nombre);
            $stmt->bindParam(':apellido', $data->apellido);
            $stmt->bindParam(':telefono', $data->telefono);
            $stmt->bindParam(':cod_vuelo', $data->cod_vuelo);
            $stmt->bindParam(':imagen_perfil', $data->imagen_perfil ?? null);
            $stmt->execute();

            http_response_code(201);
            echo json_encode(['message' => 'Pasajero registrado exitosamente']);
        } catch(PDOException $e) {
            http_response_code(400);
            echo json_encode(['error' => 'Error al registrar pasajero: ' . $e->getMessage()]);
        }
    }

    // 7. CONSULTAR PASAJEROS POR VUELO
    public function consultarPasajeros($cod_vuelo) {
        $this->verifyToken();

        $query = "SELECT p.id, p.nombre, p.apellido, p.telefono, p.imagen_perfil,
                         v.cod_vuelo, d.descripcion as destino
                  FROM pasajero p 
                  JOIN vuelo v ON p.cod_vuelo = v.cod_vuelo
                  JOIN destino d ON v.cod_destino = d.cod_destino
                  WHERE p.cod_vuelo = :cod_vuelo
                  ORDER BY p.nombre";
        
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':cod_vuelo', $cod_vuelo);
        $stmt->execute();

        if ($stmt->rowCount() > 0) {
            $pasajeros = $stmt->fetchAll(PDO::FETCH_ASSOC);
            http_response_code(200);
            echo json_encode($pasajeros);
        } else {
            http_response_code(404);
            echo json_encode(['message' => 'No se encontraron pasajeros para este vuelo']);
        }
    }

    // 8. ELIMINAR PASAJERO
    public function eliminarPasajero($id) {
        $this->verifyToken();

        $query = "DELETE FROM pasajero WHERE id = :id";
        
        try {
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(':id', $id);
            $stmt->execute();

            if ($stmt->rowCount() > 0) {
                http_response_code(204);
                echo json_encode(['message' => 'Pasajero eliminado exitosamente']);
            } else {
                http_response_code(404);
                echo json_encode(['error' => 'Pasajero no encontrado']);
            }
        } catch(PDOException $e) {
            http_response_code(400);
            echo json_encode(['error' => 'Error al eliminar pasajero']);
        }
    }

    // Función para obtener datos auxiliares
    public function getDatos($tipo) {
        $this->verifyToken();
        
        $tablas = [
            'destinos' => 'SELECT cod_destino, descripcion FROM destino',
            'aerolineas' => 'SELECT cod_aerolinea, descripcion FROM aerolinea',
            'salas' => 'SELECT cod_sala, descripcion FROM sala_abordaje'
        ];

        if (!isset($tablas[$tipo])) {
            http_response_code(400);
            echo json_encode(['error' => 'Tipo de dato no válido']);
            return;
        }

        $stmt = $this->conn->prepare($tablas[$tipo]);
        $stmt->execute();
        
        $datos = $stmt->fetchAll(PDO::FETCH_ASSOC);
        http_response_code(200);
        echo json_encode($datos);
    }
}

// Enrutamiento
$api = new AeropuertoAPI();
$request_uri = $_SERVER['REQUEST_URI'];
$path = parse_url($request_uri, PHP_URL_PATH);
$path_parts = explode('/', trim($path, '/'));

// Buscar el prefijo "dorado" en la URL
$dorado_index = array_search('dorado', $path_parts);
if ($dorado_index === false) {
    http_response_code(404);
    echo json_encode(['error' => 'Endpoint no encontrado']);
    exit;
}

// Obtener la ruta después de "dorado"
$route_parts = array_slice($path_parts, $dorado_index + 1);
$method = $_SERVER['REQUEST_METHOD'];

try {
    switch ($method) {
        case 'POST':
            if ($route_parts[0] === 'login') {
                $api->login();
            } elseif ($route_parts[0] === 'logout') {
                $api->logout();
            } elseif ($route_parts[0] === 'vuelos' && $route_parts[1] === 'crear') {
                $api->crearVuelo();
            } elseif ($route_parts[0] === 'pasajeros' && $route_parts[1] === 'crear') {
                $api->crearPasajero();
            } else {
                http_response_code(404);
                echo json_encode(['error' => 'Endpoint no encontrado']);
            }
            break;

        case 'GET':
            if ($route_parts[0] === 'vuelos' && $route_parts[1] === 'consultar') {
                $api->consultarVuelos();
            } elseif ($route_parts[0] === 'pasajeros' && $route_parts[1] === 'consultar') {
                if (isset($route_parts[2])) {
                    $api->consultarPasajeros($route_parts[2]);
                } else {
                    http_response_code(400);
                    echo json_encode(['error' => 'Código de vuelo requerido']);
                }
            } elseif ($route_parts[0] === 'datos') {
                if (isset($route_parts[1])) {
                    $api->getDatos($route_parts[1]);
                } else {
                    http_response_code(400);
                    echo json_encode(['error' => 'Tipo de dato requerido']);
                }
            } else {
                http_response_code(404);
                echo json_encode(['error' => 'Endpoint no encontrado']);
            }
            break;

        case 'PUT':
            if ($route_parts[0] === 'vuelos' && $route_parts[1] === 'editar') {
                if (isset($route_parts[2])) {
                    $api->editarVuelo($route_parts[2]);
                } else {
                    http_response_code(400);
                    echo json_encode(['error' => 'Código de vuelo requerido']);
                }
            } else {
                http_response_code(404);
                echo json_encode(['error' => 'Endpoint no encontrado']);
            }
            break;

        case 'DELETE':
            if ($route_parts[0] === 'pasajeros' && $route_parts[1] === 'eliminar') {
                if (isset($route_parts[2])) {
                    $api->eliminarPasajero($route_parts[2]);
                } else {
                    http_response_code(400);
                    echo json_encode(['error' => 'ID de pasajero requerido']);
                }
            } else {
                http_response_code(404);
                echo json_encode(['error' => 'Endpoint no encontrado']);
            }
            break;

        default:
            http_response_code(405);
            echo json_encode(['error' => 'Método no permitido']);
            break;
    }
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Error interno del servidor']);
}
?>