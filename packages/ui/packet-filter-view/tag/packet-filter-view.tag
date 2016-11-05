<packet-filter-view>
  <input class="compact" type="text" placeholder="Filter" name="filter" onkeypress={apply}>

  <style type="text/less" scoped>
    :scope {
      input {
        border-right-width: 0;
        border-left-width: 0;
        border-bottom-width: 0;
      }
    }
  </style>

  <script>
    import $ from 'jquery';
    import { Session, PubSub } from 'dripcap';

    PubSub.sub('packet-filter-view:set-filter', (text) => {
      $(this.filter).val(text);
      PubSub.pub('packet-filter-view:filter', text);
    });

    this.apply = e => {
      if (e.charCode === 13) {
        PubSub.pub('packet-filter-view:filter', $(this.filter).val());
      }
      return true;
    };

    Session.on('created', session => {
      PubSub.sub('packet-filter-view:filter', filter => session.filter('main', filter));
    });
  </script>
</packet-filter-view>
