use provisions::builders::AssetProofBuilder;
use provisions::data_source::asset::Rocks;
use rocksdb::{Options, DB};
use std::time::Instant;

#[test]
fn simple_rocks_bench() {
    let path = "rocks_test";

    {
        let now = Instant::now();
        let asset_count = 10;
        let mut asset_ds = Rocks::new(asset_count, path);
        let mut builder = AssetProofBuilder::new(&mut asset_ds);

        builder.build();

        // Remember to use -- --nocapture option when running to see this
        println!("Took: {}s", now.elapsed().as_secs());
    }

    // Cleanup
    let _ = DB::destroy(&Options::default(), path).unwrap();
}
