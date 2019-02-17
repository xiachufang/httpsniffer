use std::collections::HashMap;
use std::collections::HashSet;
use std::hash::Hash;
use std::net::ToSocketAddrs;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::RwLock;

use cadence::Counted;
use cadence::StatsdClient;

pub struct Cardinality<T: Eq + Hash> {
    name: String,
    set: Arc<RwLock<HashSet<T>>>,
}

impl<T: Eq + Hash> Cardinality<T> {
    pub fn new(name: impl Into<String>) -> Cardinality<T> {
        Cardinality {
            name: name.into(),
            set: Arc::new(RwLock::new(HashSet::new())),
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
        }
    }
}

#[derive(Clone)]
pub struct Counter {
    name: String,
    size: Arc<AtomicUsize>,
}

impl Counter {
    pub fn new(name: impl Into<String>) -> Counter {
        Counter {
            name: name.into(),
            size: Arc::new(AtomicUsize::new(0)),
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
    pub fn new(host: impl ToSocketAddrs, prefix: impl AsRef<str>) -> Self {
        Registry {
            metrics: Arc::new(RwLock::new(HashMap::new())),
            client: Arc::new(
                StatsdClient::from_udp_host(prefix.as_ref(), host).expect("statsd client"),
            ),
        }
    }

    fn new_cardinality(&self, name: impl Into<String>) -> Cardinality<T> {
        let name = name.into();
        let card = Cardinality::new(name.clone());
        self.metrics
            .write()
            .expect("new cardinality")
            .insert(name, Metric::Cardinality(card.clone()));
        card
    }

    fn new_counter(&self, name: impl Into<String>) -> Counter {
        let name = name.into();
        let counter = Counter::new(name.clone());
        self.metrics
            .write()
            .expect("new counter")
            .insert(name, Metric::Counter(counter.clone()));
        counter
    }

    pub fn get_cardinality(&self, name: &str) -> Cardinality<T> {
        if let Some(Metric::Cardinality(card)) =
            self.metrics.read().expect("get cardinality").get(name)
        {
            return card.clone();
        }
        self.new_cardinality(name)
    }

    pub fn get_counter(&self, name: &str) -> Counter {
        if let Some(Metric::Counter(counter)) = self.metrics.read().expect("get counter").get(name)
        {
            return counter.clone();
        }
        self.new_counter(name)
    }

    pub fn send(&self) {
        for (name, metric) in self.metrics.read().expect("send").iter() {
            let size = match metric {
                Metric::Cardinality(cardinality) => cardinality.flush(),
                Metric::Counter(counter) => counter.flush(),
            };

            let ret = self.client.count_with_tags(name, size as i64).try_send();
            match ret {
                Ok(..) => {}
                Err(err) => {
                    eprintln!("send error: {:?}", err);
                }
            };
        }
    }
}
