-- Your current payments table has booking_id only.
-- Run this in phpMyAdmin BEFORE using product payments.

ALTER TABLE payments
    ADD COLUMN order_id INT(11) NULL AFTER booking_id,
    ADD COLUMN payment_type VARCHAR(20) NOT NULL DEFAULT 'turf' AFTER order_id,
    MODIFY amount DECIMAL(10,2) NOT NULL,
    MODIFY transaction_id VARCHAR(255) NOT NULL;

CREATE INDEX idx_payments_booking_id ON payments (booking_id);
CREATE INDEX idx_payments_order_id ON payments (order_id);
CREATE INDEX idx_payments_type ON payments (payment_type);

-- payment_type values: turf / product
-- payment status values: pending / success / failed / refunded
