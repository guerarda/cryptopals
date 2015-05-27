(ns cryptopals.block
  (:require [cryptopals.utils :refer :all])
  (import (java.security Key)
          (javax.crypto Cipher)
          (javax.crypto.spec SecretKeySpec)))

(defn decrypt-ecb
  "input and k are bytes"
  [input k]
  (let [key (SecretKeySpec. k "AES")
        cipher (Cipher/getInstance "AES/ECB/NoPadding")]
    (.init cipher Cipher/DECRYPT_MODE key)
    (.doFinal cipher input)))

(defn encrypt-ecb
  [input k]
  (let [key (SecretKeySpec. k "AES")
        cipher (Cipher/getInstance "AES/ECB/NoPadding")]
    (.init cipher Cipher/ENCRYPT_MODE key)
    (.doFinal cipher input)))

(defn detect-ecb
  ([bsize input]
   (->> input
        (partition-all bsize)
        (#(/ (double (-  (count %) (count (distinct %)))) (count %)))
        (assoc {} :input input :score)))
  ([bsize input & more]
   (->> (cons input more)
        (map #(detect-ecb bsize %))
        (remove #(zero? (:score %))))))
