(ns cryptopals.stream
  (:require [cryptopals.utils :refer :all]
            [cryptopals.block :refer :all]))

(defn little-endian
  ([num]
   (reverse (.toByteArray (BigInteger/valueOf num))))
  ([num size]
   (take size (reverse (concat (repeat size 0) (little-endian num))))))

(defn keystream
  ([key nonce]
   (keystream key nonce 0))
  ([key nonce cnt]
   (-> (map #(little-endian % 8) (list nonce cnt))
       (flatten)
       (byte-array)
       (encrypt-ecb key)
       (cons (lazy-seq (keystream key nonce (inc cnt)))))))

(defn ctr-encrypt [msg key nonce]
  (apply concat (map byte-array-xor (partition-all 16 msg) (keystream key nonce))))
