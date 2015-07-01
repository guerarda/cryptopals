(defproject cryptopals "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.7.0"]
                 [org.clojure/data.codec "0.1.0"]
                 [ring/ring-core "1.3.2"]
                 [ring/ring-jetty-adapter "1.3.0"]
                 [compojure "1.3.4"]
                 [clj-http "1.1.2"]]
  :plugins [[lein-ring "0.9.6"]]
  :ring {:handler cryptopals.handler/app}
  :main ^:skip-aot cryptopals.core
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all}})
