(ns cryptopals.hmac
  (:require [cryptopals.utils :refer :all]
            [cryptopals.sha1 :refer :all]))

(defn hmac [hash key msg]
  (let [bs 64
        k (if (> (count key) bs)
            (hash key)
            (take bs (concat key (repeat 0))))
        opad (repeat bs 0x5c)
        ipad (repeat bs 0x36)]

    (-> (map bit-xor k opad)
        (concat (-> (map bit-xor k ipad)
                    (concat msg)
                    (sha1)))
        (sha1))))
