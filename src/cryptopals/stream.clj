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

(defn ctr-edit [cipher key nonce offset text]
  (let [pc (partition-all 16 cipher)
        txt-len (count text)
        bgn (quot offset 16)
        len (inc (- (quot (+ offset txt-len) 16) bgn))
        off (rem offset 16)
        to-replace (flatten (take len (drop bgn pc)))
        keyseq (->> (keystream key nonce)
                    (drop bgn)
                    (take len)
                    (apply concat))
        plain (apply vector (map bit-xor to-replace keyseq))
        sub-plain (subvec plain off (+ txt-len off))
        new-plain (concat (take off plain) text (drop (+ txt-len off) plain))]
    (->> (map int new-plain)
         (map bit-xor keyseq)
         (#(concat % (drop (+ bgn len) pc)))
         (concat (take bgn pc))
         (flatten))))

(defn break-ctr [cipher edit-fn]
  (let [break-byte (fn [n]
                     (first (filter #(->> (unchecked-byte %)
                                          (list)
                                          ((partial edit-fn cipher n))
                                          (drop n)
                                          (first)
                                          (= (nth cipher n))) (range 0 256))))]
    (pmap break-byte (range 0 (count cipher)))))

(defn bitflip-ctr [oracle token]
  (let [len (count token)
        prefix-len (loop [s1 (oracle "")
                          s2 (oracle "foo")
                          i 0]
                     (if (not (= (first s1) (first s2)))
                       i
                       (recur (rest s1) (rest s2) (inc i))))
        msg (map (comp unchecked-char bit-xor) (map int token) (map int (repeat \A)))
        cipher (oracle msg)
        csplit (split-at prefix-len cipher)]
    (->> (split-at (count token) (second csplit))
         (into (vector (first csplit)))
         (#(concat (first %) (map bit-xor (second %) (map int (repeat \A))) (last %))))))
