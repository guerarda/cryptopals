(ns cryptopals.dh
  (:require [cryptopals.utils :refer :all]))

(defn modexp
  [b e m]
  (loop [b (mod b m) e e x 1]
    (if (zero? e)
      x
      (if (odd? e)
        (recur (mod (* b b) m) (quot e 2) (mod (* x b) m))
        (recur (mod (* b b) m) (quot e 2) x)))))

(defn gen-public-key [sk g p]
  (modexp g sk p))

(defn gen-key [pk sk p]
  (modexp pk sk p))
