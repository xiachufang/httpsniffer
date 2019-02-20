use std::collections::HashMap;
use std::collections::HashSet;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::sync::RwLock;

use cadence::Counted;
use cadence::NopMetricSink;
use cadence::StatsdClient;

pub type CardinalityItem = String;

pub struct Cardinality {
    name: String,
    key: String,
    inner: Arc<RwLock<InnerCardinality>>,
}

struct InnerCardinality {
    tags: HashMap<String, String>,
    set: HashSet<CardinalityItem>,
}

impl InnerCardinality {
    fn new() -> Self {
        InnerCardinality {
            tags: HashMap::new(),
            set: HashSet::new(),
        }
    }
}

impl Cardinality {
    pub fn new(name: impl Into<String>, key: impl Into<String>) -> Cardinality {
        Cardinality {
            key: key.into(),
            name: name.into(),
            inner: Arc::new(RwLock::new(InnerCardinality::new())),
        }
    }

    pub fn add(&self, item: CardinalityItem) -> bool {
        self.inner.write().expect("lock write").set.insert(item)
    }

    pub fn set_tags(&self, tags: Option<HashMap<String, String>>) {
        if let Some(tags) = tags {
            self.inner.write().expect("lock write").tags = tags;
        }
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.inner.read().expect("lock read").set.len()
    }

    pub fn flush(&self) -> (usize, HashMap<String, String>) {
        let mut inner = self.inner.write().expect("lock write");
        let len = inner.set.len();
        let tags = inner.tags.clone();
        inner.set.clear();
        (len, tags)
    }
}

impl Clone for Cardinality {
    fn clone(&self) -> Self {
        Cardinality {
            key: self.key.clone(),
            name: self.name.clone(),
            inner: self.inner.clone(),
        }
    }
}

#[derive(Clone)]
pub struct Counter {
    name: String,
    key: String,
    inner: Arc<RwLock<InnerCounter>>,
}

struct InnerCounter {
    tags: HashMap<String, String>,
    size: usize,
}

impl InnerCounter {
    fn new() -> Self {
        InnerCounter {
            tags: HashMap::new(),
            size: 0,
        }
    }
}

impl Counter {
    pub fn new(name: impl Into<String>, key: impl Into<String>) -> Counter {
        Counter {
            key: key.into(),
            name: name.into(),
            inner: Arc::new(RwLock::new(InnerCounter::new())),
        }
    }

    pub fn add(&self, val: usize) -> usize {
        let mut inner = self.inner.write().expect("add");
        let old = inner.size;
        inner.size += val;
        old
    }

    pub fn set_tags(&self, tags: Option<HashMap<String, String>>) {
        if let Some(tags) = tags {
            self.inner.write().expect("lock write").tags = tags;
        }
    }

    #[allow(dead_code)]
    pub fn value(&self) -> usize {
        self.inner.read().expect("value").size
    }

    pub fn flush(&self) -> (usize, HashMap<String, String>) {
        let mut inner = self.inner.write().expect("add");
        let old = inner.size;
        let tags = inner.tags.clone();
        inner.size = 0;
        (old, tags)
    }
}

enum Metric {
    Cardinality(Cardinality),
    Counter(Counter),
}

#[derive(Clone)]
pub struct Registry {
    metrics: Arc<RwLock<HashMap<String, Metric>>>,
    client: Arc<StatsdClient>,
}

impl Registry {
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
        key: impl Into<String>,
        tags: Option<HashMap<String, String>>,
    ) -> Cardinality {
        let name = name.into();
        let key = key.into();
        let card = Cardinality::new(name.clone(), key.clone());
        card.set_tags(tags);
        self.metrics
            .write()
            .expect("new cardinality")
            .insert(name, Metric::Cardinality(card.clone()));
        card
    }

    fn new_counter(
        &self,
        name: impl Into<String>,
        key: impl Into<String>,
        tags: Option<HashMap<String, String>>,
    ) -> Counter {
        let name = name.into();
        let key = key.into();
        let counter = Counter::new(name.clone(), key.clone());
        counter.set_tags(tags);
        self.metrics
            .write()
            .expect("new counter")
            .insert(name, Metric::Counter(counter.clone()));
        counter
    }

    pub fn get_cardinality(
        &self,
        name: impl Into<String>,
        key: impl Into<String>,
        tags: Option<HashMap<String, String>>,
    ) -> Cardinality {
        let name = name.into();
        if let Some(Metric::Cardinality(card)) =
            self.metrics.read().expect("get cardinality").get(&name)
        {
            return card.clone();
        }
        self.new_cardinality(name, key, tags)
    }

    pub fn get_counter(
        &self,
        name: impl Into<String>,
        key: impl Into<String>,
        tags: Option<HashMap<String, String>>,
    ) -> Counter {
        let name = name.into();
        if let Some(Metric::Counter(counter)) = self.metrics.read().expect("get counter").get(&name)
        {
            return counter.clone();
        }
        self.new_counter(name, key, tags)
    }

    pub fn send(&self) {
        for metric in self.metrics.read().expect("send").values() {
            let (key, (size, tags)) = match metric {
                Metric::Cardinality(cardinality) => (&cardinality.key, cardinality.flush()),
                Metric::Counter(counter) => (&counter.key, counter.flush()),
            };

            let mut builder = self.client.count_with_tags(&key, size as i64);
            for (k, v) in tags.iter() {
                builder = builder.with_tag(k, v);
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
