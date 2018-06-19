//! Models and functions for analytic processing of recognised/parsed headers and other data
//! structures.

use cogset::{Euclid, Euclidean, KmeansBuilder, Point};

use std::fmt::Debug;
use std::iter::{FromIterator, IntoIterator};
use std::marker::Sized;

#[derive(Debug)]
/// A Euclidean Vector (point) generated from each potentially idiosyncratic feature found in zip
/// file headers including timestamp and flags for a given Zip header as a separate dimension in
/// Euclidean space.
///
/// We use this because the kmeans clustering algorithm essentially moves some notional
/// cluster centres around this space until they find a stable fit for proximity to the associated
/// data points for each cluster. It's a ridiculously efficient algorithm in terms of the speed at
/// which it converges to stable cluster estimates. If you're interested there's an awesome video
/// here demonstrating the practicalities of it:
/// [K-means clustering: How it works](https://www.youtube.com/watch?v=_aWzGGNrcic)
pub struct Vector<T>(pub Euclid<T>);

/// The `Vectorizable` trait indicates a quantity can be converted into
/// a Euclidean (AKA a point in R^n space).
pub trait Vectorizable {
    /// The Euclidean vector output
    type Output: Clone + Euclidean + Point;

    /// Convert a `Vectorizable` type into a vector in euclidean space.
    fn to_euclidean(&self) -> Self::Output;
}

/// An `Instance` of a particular header (with it's address for context)
pub trait Instance {
    /// The type of header item wrapped in an `Instance`
    type Item: Vectorizable;

    /// Return the address of a given header `Instance`
    fn ptr(&self) -> usize;

    /// Return the header data for a given header `Instance`
    fn header(&self) -> &Self::Item;

    /// Cluster a slice of `Vectorizable` `Instance`s, producing a collection of `k` Clusters.
    fn cluster(data: &[Self], k: usize) -> Result<Vec<Cluster<Self>>, ClusteringError>
    where
        Self: Sized;
}

#[derive(Debug)]
/// Error occurred during Clustering of headers
pub enum ClusteringError {
    /// Just throw me up and leave someone else to work out what happened
    Plain,
    /// Descriptive errors for convenience when necessary
    Descriptive(String),
}

#[derive(Clone, Debug)]
/// A cluster of header instances
pub struct Cluster<T: Instance>(Vec<T>);

impl<T: Instance + Clone> Cluster<T> {
    /// New cluster of from slice of `T` Instances
    pub fn new(instances: &[T]) -> Self {
        Cluster(Vec::from(instances))
    }
}

impl<T: Instance> IntoIterator for Cluster<T> {
    type Item = T;
    type IntoIter = ::std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[derive(Debug)]
/// An Iterator over a cluster
pub struct IterCluster<'a, T: 'a + Instance> {
    /// Cluster being iterated over
    inner: &'a Cluster<T>,
    /// Current cursor into cluster
    pos: usize
}

impl<'a, T: Instance> Iterator for IterCluster<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.inner.0.len() {
            None
        } else {
            self.pos += 1;
            self.inner.0.get(self.pos - 1)
        }
    }
}

impl<T: Instance> Cluster<T> {
    /// Convert Cluster of header instances to IterCluster
    pub fn iter(&self) -> IterCluster<T> {
        IterCluster {
            inner: self,
            pos: 0,
        }
    }
}

/// Cluster a collection of `Vectorizable` header chunk using the kmeans algorithm according to
/// their vector signatures.
///
/// Should return clusters of data points
///
/// Arguments:
///
///   `data`: `&[(usize,T)]` with generic type `T`, a zip file header format
///   `k`:    Number of clusters (i.e. zip files) expected
///
/// Return Values:
///
///   `Result<Vec<Cluster>,ClusteringError>`
///
///   A `Result` type containing wrapping either a `ClusteringError`, or better yet, a Vec of
///   clusters of pointers.
pub fn cluster<T, W>(data: &[T], k: usize) -> Result<Vec<Cluster<T>>, ClusteringError>
where
    T: Instance + Clone,
    Euclid<W>: Point + Clone + Euclidean,
    W: Debug,
    Vec<Euclid<W>>: FromIterator<<<T as Instance>::Item as Vectorizable>::Output>,
{
    let d: Vec<Euclid<W>> = data.iter()
        .map(|datum| datum.header().to_euclidean())
        .collect();

    let kmeans = KmeansBuilder::new().kmeans(&d, k);
    match kmeans.converged() {
        Ok(_) => {
            Ok(
                kmeans
                    .clusters()
                    .iter()
                    .map(|&(_, ref idxes_for_cluster)| {
                        Cluster(
                            // Map clustered data indexes back to pointers using data
                            idxes_for_cluster
                                .iter()
                                .map(|&x| data[x].clone())
                                .collect::<Vec<T>>(),
                        )
                    })
                    .collect(),
            )
        }
        Err(e) => {
            error!("Clustering failed to converge: {:?}", e);
            Err(ClusteringError::Plain)
        }
    }
}
