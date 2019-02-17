use std::collections::HashMap;
use std::collections::HashSet;
use std::hash::Hash;
use std::net::ToSocketAddrs;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::RwLock;

use cadence::Counted;
use cadence::NopMetricSink;
use cadence::StatsdClient;

pub struct Cardinality<T: Eq + Hash> {
    name: String,
    tags: Option<HashMap<String, String>>,
    set: Arc<RwLock<HashSet<T>>>,
}

impl<T: Eq + Hash> Cardinality<T> {
    pub fn new(name: impl Into<String>, tags: Option<HashMap<String, String>>) -> Cardinality<T> {
        Cardinality {
            name: name.into(),
            set: Arc::new(RwLock::new(HashSet::new())),
            tags,
        }
    }

    pub fn add(&self, item: impl Into<T>) -> bool {
        self.set.write().expect("lock write").insert(item.into())
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.set.read().expect("lock read").len()
    }

    pub fn flush(&self) -> usize {
        let mut set = self.set.write().expect("lock write");
        let len = set.len();
        set.clear();
        len
    }
}

impl<T: Eq + Hash> Clone for Cardinality<T> {
    fn clone(&self) -> Self {
        Cardinality {
            name: self.name.clone(),
            set: self.set.clone(),
            tags: self.tags.clone(),
        }
    }
}

#[derive(Clone)]
pub struct Counter {
    name: String,
    tags: Option<HashMap<String, String>>,
    size: Arc<AtomicUsize>,
}

impl Counter {
    pub fn new(name: impl Into<String>, tags: Option<HashMap<String, String>>) -> Counter {
        Counter {
            name: name.into(),
            size: Arc::new(AtomicUsize::new(0)),
            tags,
        }
    }

    pub fn add(&self, val: usize) -> usize {
        self.size.fetch_add(val, Ordering::SeqCst)
    }

    #[allow(dead_code)]
    pub fn value(&self) -> usize {
        self.size.load(Ordering::SeqCst)
    }

    pub fn flush(&self) -> usize {
        self.size.swap(0, Ordering::SeqCst)
    }
}

enum Metric<T: Eq + Hash> {
    Cardinality(Cardinality<T>),
    Counter(Counter),
}

#[derive(Clone)]
pub struct Registry<T: Eq + Hash> {
    metrics: Arc<RwLock<HashMap<String, Metric<T>>>>,
    client: Arc<StatsdClient>,
}

impl<T: Eq + Hash> Registry<T> {
    pub fn new<S: ToSocketAddrs>(host: Option<S>, prefix: impl AsRef<str>) -> Self {
        let client = match host {
            Some(h) => StatsdClient::from_udp_host(prefix.as_ref(), h).expect("statsd client"),
            None => StatsdClient::from_sink(prefix.as_ref(), NopMetricSink),
        };
        Registry {
            metrics: Arc::new(RwLock::new(HashMap::new())),
            client: Arc::new(client),
        }
    }

    fn new_cardinality(
        &self,
        name: impl Into<String>,
        tags: Option<HashMap<String, String>>,
    ) -> Cardinality<T> {
        let name = name.into();
        let card = Cardinality::new(name.clone(), tags);
        self.metrics
            .write()
            .expect("new cardinality")
            .insert(name, Metric::Cardinality(card.clone()));
        card
    }

    fn new_counter(
        &self,
        name: impl Into<String>,
        tags: Option<HashMap<String, String>>,
    ) -> Counter {
        let name = name.into();
        let counter = Counter::new(name.clone(), tags);
        self.metrics
            .write()
            .expect("new counter")
            .insert(name, Metric::Counter(counter.clone()));
        counter
    }

    pub fn get_cardinality(
        &self,
        name: &str,
        tags: Option<HashMap<String, String>>,
    ) -> Cardinality<T> {
        if let Some(Metric::Cardinality(card)) =
            self.metrics.read().expect("get cardinality").get(name)
        {
            return card.clone();
        }
        self.new_cardinality(name, tags)
    }

    pub fn get_counter(&self, name: &str, tags: Option<HashMap<String, String>>) -> Counter {
        if let Some(Metric::Counter(counter)) = self.metrics.read().expect("get counter").get(name)
        {
            return counter.clone();
        }
        self.new_counter(name, tags)
    }

    pub fn send(&self) {
        for (name, metric) in self.metrics.read().expect("send").iter() {
            let (size, tags) = match metric {
                Metric::Cardinality(cardinality) => {
                    (cardinality.flush(), cardinality.tags.as_ref())
                }
                Metric::Counter(counter) => (counter.flush(), counter.tags.as_ref()),
            };

            let mut builder = self.client.count_with_tags(name, size as i64);
            if let Some(tags) = tags {
                for (k, v) in tags.iter() {
                    builder = builder.with_tag(k, v);
                }
            }
            let ret = builder.try_send();
            match ret {
                Ok(..) => {}
                Err(err) => {
                    eprintln!("send error: {:?}", err);
                }
            };
        }
    }
}
