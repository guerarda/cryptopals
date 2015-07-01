(ns cryptopals.mt19937
  (:require [cryptopals.utils :refer :all]))

(def ^:const ^:private M 397)
(def ^:const ^:private N 624)

(defstruct mt-state :mt :index)

(defn init-mt [seed]
  (loop [mt (list (lo32 seed)) i 1]
    (if (= N i)
      (struct mt-state (reverse mt) 0)
      (recur (->> (first mt)
                  (#(bit-xor % (bit-shift-right % 30)))
                  (+ i)
                  (* 0x6c078965)
                  (lo32)
                  (conj mt))
             (inc i)))))

(defn gen-nums [mt]
  (for [i (range 0 N)]
    (let [y (->> (nth mt i)
                 (bit-and 0x80000000)
                 (+ (bit-and 0x7fffffff (nth mt (rem (inc i) N)))))
          mti (->> (+ i M)
                   (rem N)
                   (bit-xor (bit-shift-right y 1)))]
      (if (odd? y)
        (bit-xor mti 0x9908b0df)
        mti))))

(defn temper [state]
  (let [y (nth (:mt state) (:index state))]
    (->> y
         (#(bit-xor % (bit-shift-right % 11)))
         (#(bit-xor % (bit-and (bit-shift-left % 7) 0x9d2c5680)))
         (#(bit-xor % (bit-and (bit-shift-left % 15) 0xefc60000)))
         (#(bit-xor % (bit-shift-right % 18))))))

(defn next-state [state]
  (let [idx (inc (:index state))]
    (if (zero? (rem idx N))
      (struct mt-state (gen-nums (:mt state)) 0)
      (struct mt-state (:mt state) idx))))

(defn rand-seq
  ([seed]
   (->> (init-mt seed)
        (#(struct mt-state (gen-nums (:mt %)) 0))
        (rand-seq seed)))
  ([seed state]
   (cons (temper state) (lazy-seq (rand-seq seed (next-state state))))))

(defn untemper-a [x n]
  "a is the operation of xor againt a n-right-shifted value"
  (loop [i (quot 32 n) v x]
    (if (zero? i)
      v
      (recur (dec i) (bit-xor x (bit-shift-right v n))))))

(defn untemper-b [x n m]
  "b is the operation of xor against a n-left-shifted value AND'd against
   a maginc number"
  (loop [i (quot 32 n) v x]
    (if (zero? i)
      v
      (recur (dec i) (bit-xor x (bit-and m (bit-shift-left v n)))))))

(defn untemper
  ([x]
   (-> x
       (untemper-a 18)
       (untemper-b 15 0xefc60000)
       (untemper-b 7 0x9d2c5680)
       (untemper-a 11)))
  ([x & more]
   (map untemper (conj more x))))

(defn clone-state [rdm-fn untemp-fn len]
  (let [mt (map untemp-fn (take len rdm-fn))]
    (struct mt-state mt 0)))

(defn clone
  ([fstate]
   (clone fstate (struct mt-state fstate 0)))
  ([fstate state]
   (cons (temper state) (lazy-seq (clone fstate (next-state state))))))

(defn keystream [seed]
  (map unchecked-byte (rand-seq seed)))
