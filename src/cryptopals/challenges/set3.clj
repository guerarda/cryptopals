(ns cryptopals.challenges.set3
  (:require [cryptopals.utils :refer :all]
            [cryptopals.block :refer :all]
            [cryptopals.stream :refer [ctr-encrypt]]
            [cryptopals.mt19937 :refer :all :as mt19937]))

(defn challenge-17
  "The CBC padding oracle"
  []
  (let [plaintexts  (list "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc="
                          "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic="
                          "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw=="
                          "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg=="
                          "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl"
                          "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA=="
                          "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw=="
                          "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8="
                          "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g="
                          "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93")
        key (rand-byte-array 16)
        cipher-fn (fn [] (let [iv (rand-byte-array 16)
                               msg (rand-nth plaintexts)]
                           {:cipher (encrypt-cbc (pkcs7 (b64-decode msg) 16) key iv)
                            :iv iv}))
        rand-cipher (cipher-fn)
        valid? (fn [cipher iv] (try (-> cipher
                                        (decrypt-cbc key iv)
                                        (rm-pkcs7)
                                        ((constantly true)))
                                    (catch Exception e ((constantly false)))))]
    (let [n (count plaintexts)]
      (loop [s #{}]
        (if (= n (count s))
          (sort s)
          (recur (let [c (cipher-fn)
                       cipher (:cipher c)
                       iv (:iv c)]
                   (conj s (cbc-break-message valid? cipher iv 16)))))))))

(defn challenge-18
  "Implement CTR, the stream cipher mode"
  []
  (let [cipher "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
        key (.getBytes "YELLOW SUBMARINE")
        nonce 0]
    (bytes->str (ctr-encrypt (b64-decode cipher) key nonce))))

(defn challenge-19
  "Break fixed-nonce CTR mode using substitions"
  []
  (let [plaintexts (clojure.string/split-lines (slurp "resources/19.txt"))
        enc-key (rand-byte-array 16)
        ciphers (map #(ctr-encrypt (b64-decode %) enc-key 0) plaintexts)]
    (let [n (apply max (map count ciphers))
          key (->>  (for [i (range 0 n)] (map #(nth % i nil) ciphers))
                    (map (partial filter (comp not nil?)))
                    (map (comp first break-byte-xor))
                    (map :key))]

      (map #(bytes->str (byte-array-xor key %)) ciphers))))

(defn challenge-20
  "Break fixed-nonce CTR mode using statistically"
  []
  (let [plaintexts (clojure.string/split-lines (slurp "resources/20.txt"))
        enc-key (rand-byte-array 16)
        ciphers (map #(ctr-encrypt (b64-decode %) enc-key 0) plaintexts)]
    (let [n (apply max (map count ciphers))
          key (->>  (for [i (range 0 n)] (map #(nth % i nil) ciphers))
                    (map (partial filter (comp not nil?)))
                    (map (comp first break-byte-xor))
                    (map :key))]

      (map #(bytes->str (byte-array-xor key %)) ciphers))))


(defn challenge-21
  "Implement the MT19937 Mersenne Twister RNG"
  []
  (take 10 (mt19937/rand-seq 42)))

(defn challenge-22
  "Crack an MT19937 seed"
  []
  (let [w (+ 40 (rand-int 1000))
        seed (future (Thread/sleep (* w 1000)) (System/currentTimeMillis))
        num (first (mt19937/rand-seq @seed))]
    (let [break-seed (fn [n t]
                       (let [ct (System/currentTimeMillis)
                             start (- ct (* t 60 1000))]
                         (pmap (comp first #(filter (fn [x] (= n (first (mt19937/rand-seq x)))) %))
                               (partition-all 10000 (range start ct)))))]
      (first (filter (comp not nil?) (break-seed num 1000))))))

(defn challenge-23
  "Clone an MT19937 RNG from its output"
  []
  (let [rdm-seq (mt19937/rand-seq (rand-int Integer/MAX_VALUE))
        len 624
        clone-seq (mt19937/clone (map mt19937/untemper (take len rdm-seq)))]
    (= (take len rdm-seq) (take len clone-seq))))

(defn challenge-24
  "Create the MT19937 stream cipher and break it"
  []
  (let [seed (rand-int 65536)
        prefix (apply str (repeatedly (rand-int 128) (comp char #(rand-int 128))))
        keyseq (mt19937/keystream seed)
        encrypt (fn [msg] (map bit-xor (map int (concat prefix msg)) keyseq))]
    (let [n 14
          msg (repeat n \A)
          cipher (encrypt msg)
          prefix-size (- (count cipher) n)
          key-seq (map bit-xor (map int msg) (take-last n cipher))]
          (first (filter #(->> %
                         (mt19937/keystream)
                         (drop prefix-size)
                         (take n)
                         (= key-seq))
                   (range 0 65536))))))
