(ns cryptopals.sha1
  (:require [cryptopals.utils :refer [bit-rotate-left lo32 lo8]]))

(defn- bytes->int [& args]
  (let [shift-fn (fn [a b c d]
                   (bit-or (lo8 d)
                           (bit-shift-left (lo8 c) 8)
                           (bit-shift-left (lo8 b) 16)
                           (bit-shift-left (lo8 a) 24)))
        coll (concat args '(0 0 0))]
    (map #(apply shift-fn %) (partition 4 coll))))

(defn- calc-v [i w v h]
  (let [[a b c d e] v
        [f k] (cond
                (< i 20) [(bit-or (bit-and b c) (bit-and-not d b))
                          0x5a827999]
                (< i 40) [(bit-xor b c d)
                          0x6ed9eba1]
                (< i 60) [(bit-or (bit-and b c) (bit-and b d) (bit-and c d))
                          0x8f1bbcdc]
                (< i 80) [(bit-xor b c d)
                          0xca62c1d6])]
    [((comp lo32 +) (bit-rotate-left (unchecked-int a) 5) f e k (nth w i))
     a
     (bit-rotate-left (unchecked-int b) 30)
     c
     d]))

(defn- hash-chunk [h chunk]
  (let [sel (fn [v i]
              (doall (map (partial nth v)
                          (map (partial - i) '(3 8 14 16)))))
        w (loop [v (vec chunk) i 16]
            (if (= 80 i)
              v
              (recur (conj v (bit-rotate-left (unchecked-int (apply bit-xor (sel v i))) 1))
                     (inc i))))]
    (loop [v h i 0]
      (if (= 80 i)
        (mapv (comp lo32 +) h v)
        (recur (calc-v i w v h) (inc i))))))

(def ^:int ^:const ^:private h0 0x67452301)
(def ^:int ^:const ^:private h1 0xefcdab89)
(def ^:int ^:const ^:private h2 0x98badcfe)
(def ^:int ^:const ^:private h3 0x10325476)
(def ^:int ^:const ^:private h4 0xc3d2e1f0)

;; Works if input is string
;; Needs fixin

(defn sha1 [arg]
  (let [ml (count arg)
        ms (take-last 8 (concat (repeat 8 0) (.toByteArray (BigInteger/valueOf (* 8 ml)))))
        m (-> (mapv (comp unchecked-byte) (map int arg))
              (conj (unchecked-byte 0x80))
              (conj (repeat (mod (- 56 (inc ml)) 64) 0))
              (conj ms)
              (flatten))]
    (reduce hash-chunk [h0 h1 h2 h3 h4] (map (partial apply bytes->int) (partition 64 m)))))

(defn sha1-pad [len]
  (let [ms (take-last 8 (concat (repeat 8 0) (.toByteArray (BigInteger/valueOf (* 8 len)))))]
    (-> [(unchecked-byte 0x80)]
        (conj (repeat (mod (- 56 (inc len)) 64) 0))
        (conj ms)
        (flatten))))

(defn sha1-extend [arg h len]
  (let [ml (count arg)
        ms (take-last 8 (concat (repeat 8 0) (.toByteArray (BigInteger/valueOf (* 8 len)))))
        m (-> (mapv (comp unchecked-byte) (map int arg))
              (conj (unchecked-byte 0x80))
              (conj (repeat (mod (- 56 (inc ml)) 64) 0))
              (conj ms)
              (flatten))]
    (reduce hash-chunk h (map (partial apply bytes->int) (partition 64 m)))
    ))
