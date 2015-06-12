(ns cryptopals.sha1
  (:require [cryptopals.utils :refer :all]))

(defn big-add [& args]
  (bit-and 0xffffffff (apply +' args)))

(defn bytes->int [& args]
  (let [shift-fn (fn [a b c d]
                   (bit-or (lo8 d)
                           (bit-shift-left (lo8 c) 8)
                           (bit-shift-left (lo8 b) 16)
                           (bit-shift-left (lo8 a) 24)))
        coll (concat args '(0 0 0))]
    (map #(apply shift-fn %) (partition 4 coll))))

(defn calc-v [i w v h]
  (let [nv (cond
             (< i 20) (assoc v
                             :f (bit-or (bit-and (:b v) (:c v)) (bit-and-not (:d v) (:b v)))
                             :k 0x5a827999)
             (< i 40) (assoc v
                             :f (bit-xor (:b v) (:c v) (:d v))
                             :k 0x6ed9eba1)
             (< i 60) (assoc v
                             :f (bit-or (bit-and (:b v) (:c v)) (bit-and (:b v) (:d v)) (bit-and (:c v) (:d v)))
                             :k 0x8f1bbcdc)
             (< i 80) (assoc v
                             :f (bit-xor (:b v) (:c v) (:d v))
                             :k 0xca62c1d6))]
    (hash-map :a (big-add (bit-rotate-left (unchecked-int (:a nv)) 5) (:f nv) (:e nv) (:k nv) (nth w i))
              :b (:a nv)
              :c (bit-rotate-left (unchecked-int (:b nv)) 30)
              :d (:c nv)
              :e (:d nv))))


(defn hash-chunk [h chunk]
  (let [sel (fn [v i]
              (doall (map (partial nth v)
                          (map (partial - i) '(3 8 14 16)))))
        w (loop [v (vec chunk) i 16]
            (if (= 80 i)
              v
              (recur (conj v (bit-rotate-left (unchecked-int (lo32 (apply bit-xor (sel v i)))) 1))
                     (inc i))))]

    (loop [v (zipmap [:a :b :c :d :e] h) i 0]
      (if (= 80 i)
        (mapv big-add h ((juxt :a :b :c :d :e) v))

        (recur (calc-v i w v h) (inc i))))
    ))

(def ^:const ^:private h0 0x67452301)
(def ^:const ^:private h1 0xefcdab89)
(def ^:const ^:private h2 0x98badcfe)
(def ^:const ^:private h3 0x10325476)
(def ^:const ^:private h4 0xc3d2e1f0)

(defn sha1 [arg]
  (let [ml (count arg)
        ms (take-last 8 (concat (repeat 8 0) (.toByteArray (BigInteger/valueOf (* 8 ml)))))
        m (-> (mapv byte arg)
              (conj (unchecked-byte 0x80))
              (conj (repeat (mod (- 56 (inc ml)) 64) 0))
              (conj ms)
              (flatten))]
    (reduce hash-chunk (vector h0 h1 h2 h3 h4) (map (partial apply bytes->int) (partition 64 m)))
    ))
