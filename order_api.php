<?php
header("Content-Type: application/json");
require_once "../connection.php";
require_once "../config/jwt.php";

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

function response(bool $status, string $message, $data = null, int $code = 200): void {
    http_response_code($code);
    $out = ["status"=>$status,"message"=>$message];
    if ($data !== null) $out["data"] = $data;
    echo json_encode($out);
    exit;
}
function auth(): array {
    global $secret_key;
    $h = $_SERVER["HTTP_AUTHORIZATION"] ?? "";
    if (!preg_match("/Bearer\s+(.+)/i",$h,$m)) response(false,"Authorization token is required",null,401);
    try {
        $p=(array)JWT::decode(trim($m[1]),new Key($secret_key,"HS256"));
        if (($p["type"]??"")!=="access") response(false,"Invalid access token",null,401);
        if (!in_array($p["role"]??"",["user","admin"],true)) response(false,"Access denied",null,403);
        return $p;
    } catch(Throwable $e) { response(false,"Invalid or expired token",null,401); }
}

if (!isset($con) || $con->connect_error) response(false,"Database connection failed",null,500);
$user=auth();
$role=$user["role"];
$userId=(int)($user["user_id"]??$user["id"]??0);
$method=$_SERVER["REQUEST_METHOD"];
$data=json_decode(file_get_contents("php://input"),true)??[];

/* GET: USER ORDERS / ADMIN ALL ORDERS */
if ($method==="GET") {
    if ($role==="user") {
        $stmt=$con->prepare(
            "SELECT o.*,p.name AS product_name,p.category,p.image
             FROM orders o JOIN products p ON p.product_id=o.product_id
             WHERE o.user_id=? ORDER BY o.order_date DESC,o.order_id DESC"
        );
        if(!$stmt) response(false,"Failed to prepare orders",null,500);
        $stmt->bind_param("i",$userId);
    } else {
        $stmt=$con->prepare(
            "SELECT o.*,p.name AS product_name,p.category,p.image
             FROM orders o JOIN products p ON p.product_id=o.product_id
             ORDER BY o.order_date DESC,o.order_id DESC"
        );
        if(!$stmt) response(false,"Failed to prepare orders",null,500);
    }
    $stmt->execute();
    $r=$stmt->get_result();
    $orders=[];
    while($row=$r->fetch_assoc()) $orders[]=$row;
    $stmt->close();
    response(true,"Orders fetched successfully",$orders);
}

/* POST: CREATE ORDER FROM CART ITEMS */
if ($method==="POST") {
    if($role!=="user") response(false,"Only users can create orders",null,403);
    $items=$data["items"]??[];
    if(!is_array($items)||count($items)===0) response(false,"Order items are required",null,422);

    $con->begin_transaction();
    try {
        $created=[];
        $total=0.0;

        foreach($items as $item) {
            $productId=(int)($item["product_id"]??0);
            $qty=(int)($item["quantity"]??0);
            if($productId<=0||$qty<=0) throw new Exception("Invalid product_id or quantity");

            $p=$con->prepare(
                "SELECT product_id,name,price,stock,status FROM products
                 WHERE product_id=? LIMIT 1 FOR UPDATE"
            );
            if(!$p) throw new Exception($con->error);
            $p->bind_param("i",$productId);
            $p->execute();
            $r=$p->get_result();
            if($r->num_rows===0) throw new Exception("Product not found");
            $product=$r->fetch_assoc();
            $p->close();

            if(strtolower((string)$product["status"])!=="available")
                throw new Exception("Product is not available: ".$product["name"]);
            if((int)$product["stock"]<$qty)
                throw new Exception("Insufficient stock: ".$product["name"]);

            $amount=(float)$product["price"]*$qty;

            $i=$con->prepare(
                "INSERT INTO orders(user_id,product_id,quantity,amount,status,order_date)
                 VALUES(?,?,?,?,'pending',CURDATE())"
            );
            if(!$i) throw new Exception($con->error);
            $i->bind_param("iiid",$userId,$productId,$qty,$amount);
            if(!$i->execute()) throw new Exception($i->error);
            $orderId=$i->insert_id;
            $i->close();

            $s=$con->prepare("UPDATE products SET stock=stock-? WHERE product_id=?");
            if(!$s) throw new Exception($con->error);
            $s->bind_param("ii",$qty,$productId);
            if(!$s->execute()) throw new Exception($s->error);
            $s->close();

            $total += $amount;
            $created[]=[
                "order_id"=>(int)$orderId,
                "product_id"=>$productId,
                "product_name"=>$product["name"],
                "quantity"=>$qty,
                "amount"=>$amount,
                "status"=>"pending"
            ];
        }

        $con->commit();
        response(true,"Order created successfully",[
            "user_id"=>$userId,
            "total_amount"=>$total,
            "orders"=>$created
        ],201);
    } catch(Throwable $e) {
        $con->rollback();
        response(false,$e->getMessage(),null,409);
    }
}

/* ADMIN: UPDATE ORDER STATUS */
if($method==="PATCH"||$method==="PUT") {
    if($role!=="admin") response(false,"Only admin can update order status",null,403);
    $orderId=(int)($data["order_id"]??0);
    $status=strtolower(trim($data["status"]??""));
    $allowed=["pending","paid","processing","shipped","delivered","cancelled"];
    if($orderId<=0||!in_array($status,$allowed,true))
        response(false,"Valid order_id and status are required",null,422);

    $stmt=$con->prepare("UPDATE orders SET status=? WHERE order_id=?");
    if(!$stmt) response(false,"Failed to prepare order update",null,500);
    $stmt->bind_param("si",$status,$orderId);
    if(!$stmt->execute()) response(false,"Failed to update order",null,500);
    if($stmt->affected_rows===0){$stmt->close();response(false,"Order not found",null,404);}
    $stmt->close();
    response(true,"Order status updated successfully");
}

/* USER: CANCEL PENDING ORDER */
if($method==="DELETE") {
    if($role!=="user") response(false,"Only users can cancel their orders",null,403);
    $orderId=(int)($data["order_id"]??$_GET["order_id"]??0);
    if($orderId<=0) response(false,"order_id is required",null,422);

    $con->begin_transaction();
    try {
        $stmt=$con->prepare(
            "SELECT product_id,quantity,status FROM orders
             WHERE order_id=? AND user_id=? LIMIT 1 FOR UPDATE"
        );
        if(!$stmt) throw new Exception($con->error);
        $stmt->bind_param("ii",$orderId,$userId);
        $stmt->execute();
        $r=$stmt->get_result();
        if($r->num_rows===0) throw new Exception("Order not found");
        $o=$r->fetch_assoc();
        $stmt->close();

        if(strtolower($o["status"])!=="pending")
            throw new Exception("Only pending orders can be cancelled");

        $u=$con->prepare("UPDATE orders SET status='cancelled' WHERE order_id=? AND user_id=?");
        if(!$u) throw new Exception($con->error);
        $u->bind_param("ii",$orderId,$userId);
        $u->execute();
        $u->close();

        $s=$con->prepare("UPDATE products SET stock=stock+? WHERE product_id=?");
        if(!$s) throw new Exception($con->error);
        $qty=(int)$o["quantity"]; $pid=(int)$o["product_id"];
        $s->bind_param("ii",$qty,$pid);
        $s->execute(); $s->close();

        $con->commit();
        response(true,"Order cancelled successfully");
    } catch(Throwable $e) {
        $con->rollback();
        response(false,$e->getMessage(),null,409);
    }
}
response(false,"Unsupported request",null,405);
?>