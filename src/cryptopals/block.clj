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
        (map (partial detect-ecb bsize))
        (remove #(zero? (:score %))))))

(defn encrypt-cbc
  "Inputs and output are in bytes"
  [arg key iv]
  (loop [cipher (list (take 16 iv))
         plaintext (partition-all 16 arg)]
    (if (zero? (count plaintext))
      (do ((comp byte-array flatten rest reverse) cipher))
      (recur (->> (first cipher)
                  (byte-array-xor (first plaintext))
                  (#(encrypt-ecb % key))
                  (map int)
                  (conj cipher))
             (rest plaintext)))))

(defn decrypt-cbc
  "inputs and output are in bytes"
  ([arg key iv]
   (-> arg
       (decrypt-ecb key)
       (byte-array-xor (byte-array (into (map int arg) (reverse (map int (take 16 iv))))))))
  ([arg key]
   (decrypt-cbc arg key (repeat 16 0))))

(defn random-pad
  "Pad arg with a b a random number of times"
  [arg b]
  (-> []
      (into (repeat (+ 5 (rand-int 5)) b))
      (into arg)
      (into (repeat (+ 5 (rand-int 5)) b))
      (byte-array)))

(defn encryption-oracle
  [arg]
  (let [key (rand-byte-array 16)
        enc-fn (if (zero? (rand-int 2))
                 (fn [x] (encrypt-ecb x key))
                 (fn [x] (encrypt-cbc x key (rand-byte-array 16))))]
    (-> (random-pad arg 0)
        (pkcs7 16)
        ((comp enc-fn byte-array)))))

(defn detect-mode
  [arg]
  (if (zero? (:score (detect-ecb 16 arg)))
    (str "CBC")
    (str "ECB")))

(defn find-prefix-size
  "For challenge 14, find the size of the prefix"
  [oracle bs]
  (let [cipher (oracle (repeat (* 3 bs) 0))
        first-dupl (fn [x] (loop [seq (partition bs x) i 0]
                                (cond
                                  (apply = (take 2 seq)) i
                                  (= i (count x)) -1
                                  :else (recur (rest seq) (inc i)))))
        block-index (first-dupl cipher)]

    (loop [pad-size (* 3 bs)]
      (if (= (first-dupl (oracle (repeat pad-size 0))) block-index)
        (recur (dec pad-size))
        (- (* block-index bs ) (rem (inc pad-size) bs))))))


(defn ecb-break-byte
  "Given an oracle, block size, prefix size and the known message,
  fin the next byte"
  [oracle-fn bs ps msg]
  (let [pad-size (- bs (rem ps bs))
        block-offset (inc (quot ps bs))
        insize (+ pad-size (- (dec bs) (rem (count msg) bs)))
        block-index (+ block-offset (quot (count msg) bs))
        enc-byte (fn [x] (->> (concat (list (unchecked-byte x)) (reverse msg) (repeat \A))
                              (take (+ pad-size bs))
                              (reverse)
                              (oracle-fn)
                              (partition bs)
                              (#(nth % block-offset))))
        results (group-by enc-byte (range 0 256))]

    (let [cipher (->> (repeat insize \A)
                      (oracle-fn)
                      (partition bs))]
      (when-let [b (-> cipher
                     (nth block-index)
                     ((partial get results)))]
        (unchecked-char (first b))))))

(defn ecb-break-message
  [enc-fn bs]
  (let [ps (find-prefix-size enc-fn bs)
        ms (- (count (enc-fn "")) ps)]
    (loop [plaintext nil s ms]
      (if (zero? s)
        plaintext
        (recur (str plaintext (ecb-break-byte enc-fn bs ps plaintext))
               (dec s))))))

(defn cbc-bitflip [enc-fn valid-fn bs msg]
  (when (< (count msg) bs)
    (let [str "yellow submarine"
          input (->> msg
                   (concat (repeat 16 \A))
                   (take-last 16)
                   (byte-array-xor str)
                   (map char)
                   (concat str))] ;; Should check if input contains ; or = and if so, modify str
      (loop [in input]
        (let [cipher (enc-fn in)
              valid-cipher (->> cipher
                                (partition 16)
                                (map #(hash-map % (map int (byte-array-xor % str))))
                                (map #(byte-array (flatten (replace % (partition 16 cipher)))))
                                (filter valid-fn)
                                (first))]
          (if (nil? valid-cipher)
            (recur (concat (list \A) in))
            (hash-map :input in :new-cipher valid-cipher)))))))

(defn cbc-break-byte [pad-oracle cipher-block arg bs]
  (let [n (inc (count arg))
        in (map int (byte-array-xor arg (repeat bs n)))
        blocks (map #(take-last bs (into (conj in %) (repeat bs 0))) (range 0 256))]
    (when-let [guess (first (filter #(pad-oracle (byte-array (concat % cipher-block)) (repeat bs 0)) blocks))]
      (byte-array-xor (repeat 16 n) guess))))

(defn cbc-break-block [pad-oracle cipher-block bs]
  (loop [guess nil i bs]
    (if (zero? i)
      guess
      (recur (drop (dec i) (cbc-break-byte pad-oracle cipher-block guess bs)) (dec i)))))

(defn cbc-break-message [pad-oracle cipher iv bs]
  (->> (partition bs cipher)
       (map #(cbc-break-block pad-oracle % bs))
       (flatten)
       (byte-array-xor (concat iv cipher))
       (rm-pkcs7)
       (map char)
       (apply str)))
