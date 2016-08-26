(ns cryptopals.utils
  (:require [clojure.data.codec.base64 :as b64]))

(defn lo8 [x]
  (bit-and 0xff x))

(defn lo32 [x]
  (bit-and 0xffffffff x))

(defn bytes->str [x]
  (apply str (map unchecked-char x)))

(defn bytes->hex [x]
  (apply str (map (partial format "%02x") x)))

(defn bytes->int [& args]
  (let [shift-fn (fn [a b c d]
                   (bit-or (lo8 d)
                           (bit-shift-left (lo8 c) 8)
                           (bit-shift-left (lo8 b) 16)
                           (bit-shift-left (lo8 a) 24)))
        coll (concat args '(0 0 0))]
    (map #(apply shift-fn %) (partition 4 coll))))

(defn num->bytes
  ([num]
   (let [x (BigInteger/valueOf num)]
     (->> (range 0 (.bitLength x) 8)
          (map  #(.shiftRight x %))
          (map #(.and % (BigInteger/valueOf 0xff)))
          (map unchecked-byte)
          (reverse)))))

(defn b64-decode [arg]
  (b64/decode (.getBytes arg)))

(defn hex-decode [arg]
  (let [x (if (odd? (count arg))
            (str 0 arg)
            arg)]
    (->> x
         (partition 2)
         (map #(apply str %))
         (map #(Integer/parseInt % 16)))))

(defn byte-array-xor
  [a b]
  (byte-array (map bit-xor (map int a) (map int b))))

(defn bit-rotate-left [x n]
  (cond
    (instance? Integer x) (Integer/rotateLeft x n)
    (instance? Long x) (Long/rotateLeft x n)))

(defn bit-rotate-right [x n]
  (cond
    (instance? Integer x) (Integer/rotateRight x n)
    (instance? Long x) (Long/rotateRight x n)))

(defn rand-bigint [num]
  "Return random bigint below num, the same as (rand-int n)"
  (loop []
    (let [val (BigInteger. (.bitLength (bigint num)) (java.util.Random.))]
      (if (< val num) val (recur)))))

(defn rand-byte-array
  [size]
  (byte-array (repeatedly size #(- 128 (rand-int 256)))))

(defn frequencies-norm
  [arg]
  (let [sum (count arg)]
    (reduce-kv (fn [m k v]
                 (assoc m k (double (/ v sum)))) {} (frequencies arg))))

(defn distance-map
  [m1 m2]
  (let [m (merge-with - m1 m2)]
    (Math/sqrt (reduce-kv (fn [i k v]
                            (+ (* v v) i)) 0 m))))
(defn score-english-text
  "Compare char frequency of a str to the one of the english language"
  [arg]
  (let [eng-freq
        {\a 0.0651738
         \b 0.0124248
         \c 0.0217339
         \d 0.0349835
         \e 0.1041442
         \f 0.0197881
         \g 0.0158610
         \h 0.0492888
         \i 0.0558094
         \j 0.0009033
         \k 0.0050529
         \l 0.0331490
         \m 0.0202124
         \n 0.0564513
         \o 0.0596302
         \p 0.0137645
         \q 0.0008606
         \r 0.0497563
         \s 0.0515760
         \t 0.0729357
         \u 0.0225134
         \v 0.0082903
         \w 0.0171272
         \x 0.0013692
         \y 0.0145984
         \z 0.0007836
         \space 0.1918182}]
    (distance-map eng-freq (frequencies-norm (clojure.string/lower-case arg)))))

(defn repeat-xor [arg b]
  (map bit-xor (map int arg) (flatten (repeat b))))


(defn break-byte-xor
  ([arg]
   (break-byte-xor arg score-english-text))
  ([arg score-fn]
   (let [key-fn (fn [x] (->> (repeat-xor arg (unchecked-byte x))
                             (bytes->str)
                             (hash-map :key (unchecked-byte x) :message)
                             (#(assoc % :score (score-fn (:message %))))))]
     (sort-by :score < (map key-fn (range 0 256))))))

(defn hamming-distance
  "Compute the hamming distance between two seq of bytes"
  [b1 b2]
  (let [reduce-byte (fn [x] (count (filter true? (map #(bit-test x %) '(0 1 2 3 4 5 6 7)))))]
    (reduce + (map reduce-byte (map #(bit-xor %1 %2) b1 b2)))))

(defn edit-score
  "Normalized edit distance for key of size ks"
  [b1 b2]
  (/ (hamming-distance b1 b2) (count b1)))

(defn keysize-score
  [arg ks nb]
  (->> arg
       (partition ks)
       (partition 2)
       (map #(apply edit-score %))
       (take nb)
       (reduce +)
       (double)
       (* (/ 1 nb))))

(defn keysize-guess
  [arg nb maxks]
  (->> (range 2 (inc maxks))
       (map #(hash-map :keysize % :score (keysize-score arg % nb)))
       (sort-by :score)))

(defn break-repeat-xor
  [cipher ks]
  (->> (for [n (range 0 ks)]
         (map #(nth % n nil) (partition-all ks cipher)))
       (map (partial filter (comp not nil?)))
       (map (comp first break-byte-xor))
       (map :key)))

(defn pkcs7
  [arg len]
  (let [nb (- len (rem (count arg) len))]
    (into (repeat nb (byte nb)) (reverse (map byte arg)))))

(defn rm-pkcs7 [arg]
  (let [n (int (last arg))]
    (cond
      (not (pos? n)) (throw (Exception. "PKCS#7 Bad padding"))
      (not (apply = (take-last n arg))) (throw (Exception. "PKCS#7 Bad padding"))
      :else (drop-last n arg))))

(defn parse-kv [arg sep1 sep2]
  (->> (clojure.string/split arg (re-pattern (str sep1)))
       (map #(clojure.string/split % (re-pattern (str sep2))))
       (flatten)
       (apply hash-map)
      ; (clojure.walk/keywordize-keys)
       ))

(defn admin?
  "Decrypt and test if the string contains admin=true"
  [decrypt-fn sep1 sep2 cipher]
  (if-let [msg (->> (decrypt-fn cipher)
                   ; (#(decrypt-cbc % encryption-key (repeat 0)))
                   ; (remove-pkcs7-pad)
                    )]
    (->> msg
         (map unchecked-char)
         (apply str)
         (#(clojure.string/split % (re-pattern (str sep1))))
         (map #(clojure.string/split % (re-pattern (str sep2))))
         (filter #(even? (count %)))
         (flatten)
         (apply hash-map)
        ; (clojure.walk/keywordize-keys)
         (:admin)
         (= "true"))
    false))

(defn benchmark [fn & args]
  (let [start (System/nanoTime)
        ret (apply fn args)]
    {:ret ret :time (/ (double (- (System/nanoTime) start)) 1000000.)}))
