(ns cryptopals.sha1-test
  (:require [clojure.test :refer :all]
            [cryptopals.sha1 :refer :all]
            [cryptopals.utils :refer [bytes->hex]]))

(deftest sha1-test
  (testing "Input: abc"
    (let [arg "abc"]
      (is (= "a9993e364706816aba3e25717850c26c9cd0d89d" (bytes->hex (sha1 arg))))))
  (testing "Input: empty"
    (is (= "da39a3ee5e6b4b0d3255bfef95601890afd80709" (bytes->hex (sha1 "")))))
  (testing "Vector #3"
    (let [arg "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"]
      (is (= "84983e441c3bd26ebaae4aa1f95129e5e54670f1" (bytes->hex (sha1 arg))))))
  (testing "Vector #4"
    (let [arg "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"]
      (is (= "a49b2446a02c645bf419f995b67091253a04a259" (bytes->hex (sha1 arg))))))
  (testing "1 000 000 \"a\""
    (let [arg (apply str (repeat 1000000 "a"))]
      (is (= "34aa973cd4c4daa4f61eeb2bdbad27316534016f" (bytes->hex (sha1 arg)))))))
