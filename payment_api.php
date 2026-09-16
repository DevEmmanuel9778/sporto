<?php
header("Content-Type: application/json");
require_once "../connection.php";
require_once "../config/jwt.php";

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

function response(bool $status,string $message,$data=null,int $code=200):void{
    http_response_code($code);
    $out=["status"=>$status,"message"=>$message];
    if($data!==null)$out["data"]=$data;
    echo json_encode($out); exit;
}
function auth():array{
    global $secret_key;
    $h=$_SERVER["HTTP_AUTHORIZATION"]??"";
    if(!preg_match("/Bearer\s+(.+)/i",$h,$m)) response(false,"Authorization token is required",null,401);
    try{
        $p=(array)JWT::decode(trim($m[1]),new Key($secret_key,"HS256"));
        if(($p["type"]??"")!=="access") response(false,"Invalid access token",null,401);
        if(!in_array($p["role"]??"",["user","owner","admin"],true)) response(false,"Access denied",null,403);
        return $p;
    }catch(Throwable $e){response(false,"Invalid or expired token",null,401);}
}

if(!isset($con)||$con->connect_error) response(false,"Database connection failed",null,500);
$user=auth(); $role=$user["role"]; $userId=(int)($user["user_id"]??$user["id"]??0);
$method=$_SERVER["REQUEST_METHOD"];
$data=json_decode(file_get_contents("php://input"),true)??[];

/*
REQUIRED payments columns for both turf and product payments:
payment_id, booking_id, order_id, payment_type, amount,
payment_method, transaction_id, status, payment_date
*/

/* POST: USER PAYMENT */
if($method==="POST"){
    if($role!=="user") response(false,"Only users can make payments",null,403);

    $type=strtolower(trim($data["payment_type"]??""));
    $methodName=trim($data["payment_method"]??"");
    $transactionId=trim((string)($data["transaction_id"]??""));

    if(!in_array($type,["turf","product"],true)) response(false,"payment_type must be turf or product",null,422);
    if($methodName===""||$transactionId==="") response(false,"payment_method and transaction_id are required",null,422);

    $con->begin_transaction();
    try{
        if($type==="turf"){
            $bookingId=(int)($data["booking_id"]??0);
            if($bookingId<=0) throw new Exception("booking_id is required");

            $stmt=$con->prepare(
                "SELECT booking_id,amount,status FROM bookings
                 WHERE booking_id=? AND user_id=? LIMIT 1 FOR UPDATE"
            );
            if(!$stmt) throw new Exception($con->error);
            $stmt->bind_param("ii",$bookingId,$userId); $stmt->execute();
            $r=$stmt->get_result();
            if($r->num_rows===0) throw new Exception("Booking not found");
            $b=$r->fetch_assoc(); $stmt->close();

            if(in_array(strtolower($b["status"]),["paid","completed"],true))
                throw new Exception("Booking is already paid");

            $amount=(float)$b["amount"];
            $i=$con->prepare(
                "INSERT INTO payments
                 (booking_id,order_id,payment_type,amount,payment_method,transaction_id,status,payment_date)
                 VALUES (?,NULL,'turf',?,?,?,'success',CURDATE())"
            );
            if(!$i) throw new Exception($con->error);
            $i->bind_param("idss",$bookingId,$amount,$methodName,$transactionId);
            if(!$i->execute()) throw new Exception($i->error);
            $paymentId=$i->insert_id; $i->close();

            $u=$con->prepare("UPDATE bookings SET status='paid' WHERE booking_id=? AND user_id=?");
            if(!$u) throw new Exception($con->error);
            $u->bind_param("ii",$bookingId,$userId); $u->execute(); $u->close();

            $con->commit();
            response(true,"Turf payment successful",[
                "payment_id"=>(int)$paymentId,"payment_type"=>"turf",
                "booking_id"=>$bookingId,"amount"=>$amount,
                "payment_method"=>$methodName,"transaction_id"=>$transactionId,"status"=>"success"
            ],201);
        }

        $orderId=(int)($data["order_id"]??0);
        if($orderId<=0) throw new Exception("order_id is required");

        $stmt=$con->prepare(
            "SELECT order_id,amount,status FROM orders
             WHERE order_id=? AND user_id=? LIMIT 1 FOR UPDATE"
        );
        if(!$stmt) throw new Exception($con->error);
        $stmt->bind_param("ii",$orderId,$userId); $stmt->execute();
        $r=$stmt->get_result();
        if($r->num_rows===0) throw new Exception("Order not found");
        $o=$r->fetch_assoc(); $stmt->close();

        if(in_array(strtolower($o["status"]),["paid","delivered"],true))
            throw new Exception("Order is already paid");

        $amount=(float)$o["amount"];
        $i=$con->prepare(
            "INSERT INTO payments
             (booking_id,order_id,payment_type,amount,payment_method,transaction_id,status,payment_date)
             VALUES (NULL,?,'product',?,?,?,'success',CURDATE())"
        );
        if(!$i) throw new Exception($con->error);
        $i->bind_param("idss",$orderId,$amount,$methodName,$transactionId);
        if(!$i->execute()) throw new Exception($i->error);
        $paymentId=$i->insert_id; $i->close();

        $u=$con->prepare("UPDATE orders SET status='paid' WHERE order_id=? AND user_id=?");
        if(!$u) throw new Exception($con->error);
        $u->bind_param("ii",$orderId,$userId); $u->execute(); $u->close();

        $con->commit();
        response(true,"Product payment successful",[
            "payment_id"=>(int)$paymentId,"payment_type"=>"product",
            "order_id"=>$orderId,"amount"=>$amount,
            "payment_method"=>$methodName,"transaction_id"=>$transactionId,"status"=>"success"
        ],201);
    }catch(Throwable $e){
        $con->rollback();
        response(false,$e->getMessage(),null,409);
    }
}

/* GET: USER OWN / OWNER TURF PAYMENTS / ADMIN ALL */
if($method==="GET"){
    if($role==="user"){
        $stmt=$con->prepare(
            "SELECT p.* FROM payments p
             LEFT JOIN bookings b ON b.booking_id=p.booking_id
             LEFT JOIN orders o ON o.order_id=p.order_id
             WHERE (p.payment_type='turf' AND b.user_id=?)
                OR (p.payment_type='product' AND o.user_id=?)
             ORDER BY p.payment_date DESC,p.payment_id DESC"
        );
        if(!$stmt) response(false,"Failed to prepare payments",null,500);
        $stmt->bind_param("ii",$userId,$userId);
    }elseif($role==="owner"){
        $stmt=$con->prepare(
            "SELECT p.* FROM payments p
             JOIN bookings b ON b.booking_id=p.booking_id
             JOIN turf_tb t ON t.turf_id=b.turf_id
             WHERE p.payment_type='turf' AND t.owner_id=?
             ORDER BY p.payment_date DESC,p.payment_id DESC"
        );
        if(!$stmt) response(false,"Failed to prepare payments",null,500);
        $stmt->bind_param("i",$userId);
    }else{
        $stmt=$con->prepare("SELECT * FROM payments ORDER BY payment_date DESC,payment_id DESC");
        if(!$stmt) response(false,"Failed to prepare payments",null,500);
    }
    $stmt->execute(); $r=$stmt->get_result(); $payments=[];
    while($row=$r->fetch_assoc())$payments[]=$row;
    $stmt->close();
    response(true,"Payments fetched successfully",$payments);
}

/* ADMIN: UPDATE PAYMENT STATUS */
if($method==="PATCH"||$method==="PUT"){
    if($role!=="admin") response(false,"Only admin can update payment status",null,403);
    $paymentId=(int)($data["payment_id"]??0);
    $status=strtolower(trim($data["status"]??""));
    $allowed=["pending","success","failed","refunded"];
    if($paymentId<=0||!in_array($status,$allowed,true))
        response(false,"Valid payment_id and status are required",null,422);

    $stmt=$con->prepare("UPDATE payments SET status=? WHERE payment_id=?");
    if(!$stmt) response(false,"Failed to prepare payment update",null,500);
    $stmt->bind_param("si",$status,$paymentId);
    if(!$stmt->execute()) response(false,"Failed to update payment",null,500);
    if($stmt->affected_rows===0){$stmt->close();response(false,"Payment not found",null,404);}
    $stmt->close();
    response(true,"Payment status updated successfully");
}
response(false,"Unsupported request",null,405);
?>