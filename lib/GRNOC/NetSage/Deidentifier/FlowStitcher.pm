package GRNOC::NetSage::Deidentifier::FlowStitcher;

use strict;
use warnings;

use Moo;

extends 'GRNOC::NetSage::Deidentifier::Pipeline';

use GRNOC::Log;
use GRNOC::Config;

#use Data::Validate::IP;
#use Net::IP;
#use Digest::SHA;

#use JSON::XS;
use Clone qw(clone);
use IPC::Shareable;
use IPC::ShareLite;
use Storable qw(freeze thaw);
use Try::Tiny;
use Number::Bytes::Human qw(format_bytes);
use Time::Duration;
use Time::HiRes;

use Data::Dumper;

### internal attributes ###

has handler => ( is => 'rwp');

#has input_data => ( is => 'rwp', default => [] );

has flow_cache => ( is => 'rwp' );

has knot => ( is => 'rwp' );

has acceptable_offset => ( is => 'rwp', default => 5 );

has finished_flows => ( is => 'rwp', default => sub { [] } );

#has ipv4_bits_to_strip => ( is => 'rwp', default => 8 );
#has ipv6_bits_to_strip => ( is => 'rwp', default => 64 );

### constructor builder ###

sub BUILD {

    my ( $self ) = @_;

    my $config_obj = $self->config;
    my $config = $config_obj->get('/config');
    # warn "config: " . Dumper $config;
    #my $anon = $config->{'deidentification'};
    #my $ipv4_bits = $config->{'deidentification'}->{'ipv4_bits_to_strip'};
    #my $ipv6_bits = $config->{'deidentification'}->{'ipv6_bits_to_strip'};
    #$self->_set_ipv4_bits_to_strip( $ipv4_bits );
    #$self->_set_ipv6_bits_to_strip( $ipv6_bits );
    $self->_set_handler( sub { $self->_run_flow_stitching(@_) } );

    #$self->_run_flow_stitching();

    return $self;
}

### private methods ###
sub _init_cache {
    my $self = shift;
    my $glue = 'flow';
    my %options = (
        create    => 0,
        exclusive => 0,
        mode      => 0644,
        destroy   => 0,
    );
    my %cache;
    my $knot = tie %cache, 'IPC::Shareable', $glue, { %options } or die "client: tie failed\n";
    warn "cache: " . Dumper %cache;

    #$cache->{'set_from_stitcher'} = 'DUH!';

    $self->_set_flow_cache( \%cache );
    $self->_set_knot( $knot );

}

# expects an array of data for it to stitch
# returns a stitched array? TODO: update this
sub _run_flow_stitching {
    my ( $self, $caller, $messages ) = @_;

    #$self->_init_cache();

    $self->_stitch_flows( );


    #foreach my $message ( @$messages ) {
        #my $src_ip = $message->{'meta'}->{'src_ip'};
        #my $dst_ip = $message->{'meta'}->{'dst_ip'};
        #my $id = $self->_generate_id( $message );
        #$message->{'meta'}->{'id'} = $id;
        #$message->{'meta'}->{'src_ip'} = $self->_deidentify_ip( $src_ip );
        #$message->{'meta'}->{'dst_ip'} = $self->_deidentify_ip( $dst_ip );
    #}

    # Flow stitching is a special case in the pipeline in that it doesn't simply
    # return values to be stitched and then exit. It explicitly publishes them itself
    # and returns an empty array when it's done. This is because it's a long-running process
    # that looks at flows over time
    $self->_publish_flows( );

    #return $finished_messages;
    my $finished_messages = $self->_get_flows();
    warn "finished messagesS: " . Dumper $finished_messages;
    
    return ( $finished_messages );
}

sub _publish_flows {
    my $self = shift;
    my $flows = $self->finished_flows;
    warn "publishing flows ... " . Dumper $flows;
    # TODO: fix an issue where flows aren't deleted after being published
    $self->_publish_data( $flows );
}

sub _stitch_flows {
    my ( $self ) = @_;

    my $glue = 'flow';
    my %options = (
        create    => 0,
        exclusive => 0,
        mode      => 0644,
        destroy   => 0,
    );
    my $cache;
    my $share = IPC::ShareLite->new(
        -key => 'flow',
        -create => 'yes',
        -destroy => 'no',
    ) or die $!;
    if ( not defined $self->flow_cache ) {
        warn "initially creating cache ..."; 
        $cache = {};
    } else {
        warn "thawing cache ...";
        $cache = thaw( $share->fetch );
    }
    $self->_set_flow_cache( $cache );

    warn "stitcher cache: " . keys %$cache; # . Dumper $cache;
    #warn "self: " . Dumper $self;

    my $overlaps = 0;
    my $stitchable_flows = 0;

    #$knot->shlock();
    warn "looping through cache";
    while( my ( $five_tuple, $flow_container ) = each %$cache ) {
        warn "ft: $five_tuple";
        my $flows = $flow_container->{'flows'};
        if ( @$flows > 1 ) {
            my $previous_flow;
            my $i = 0;
            my %flows_to_remove = ();
            foreach my $flow (@$flows ) {
                my $start = $flow->{'start'};
                my $end = $flow->{'end'};
                $flow->{'flow_num'} = $i;
                # If there is a previous flow
                if ( $previous_flow ) {
                    # If this flow and the previous flow go together, merge them 
                    # and remove previous flow
                    if ( $self->_can_stitch_flow( $previous_flow->{'end'}, $start ) ) {
                        $flow = $self->_stitch_flow( $previous_flow, $flow );
                        $flows_to_remove{$i-1} = 1;
                        $stitchable_flows++;
                    } else {
                        # TODO: review. If can't stitch flows, that means that flow has ended and can be output and removed from the cache
                        #$self->_publish_data( $flow );
                        push @{ $self->finished_flows }, %{ clone $flow};
                        $flows_to_remove{$i} = 1;
                    }

                }
                $previous_flow = $flow;
                $i++;
            }

            for (my $i=@$flows-1; $i>=0; $i--) {
                if ( $flows_to_remove{$i} ) {
                    #warn "removing flow $i";
                    splice @$flows, $i, 1;
                }

            }

        }

    }

    #$knot->shunlock();

    # find stats on the final, stitched flows
    my $max_stitched_duration = 0;
    my $max_stitched_bytes = 0;
    my $min_stitched_duration;
    while( my ( $five_tuple, $flow_container ) = each %$cache ) {
        foreach my $row ( @{$flow_container->{'flows'}} ) {
            my $bytes = $row->{'values'}->{'num_bits'} / 8;
            my $duration = $row->{'values'}->{'duration'};
            if ( $duration > $max_stitched_duration ) {
                $max_stitched_duration = $duration;
            }
            if ( $bytes > $max_stitched_bytes ) {
                $max_stitched_bytes = $bytes;
            }
        }

    }



    #warn Dumper $cache;

    my $stitched_flows = $self->_get_flows('stitched');
    warn "STITCHED FLOWS:" . Dumper $stitched_flows;
    #warn "ALL DATA:" . Dumper $input_data;

    warn "STITCHED FLOW COUNT: " . @$stitched_flows;
    #output_csv($stitched_flows);

    warn "overlaps: $overlaps";
    warn "stitchable flows: $stitchable_flows";
    warn "max stitched duration: " . duration($max_stitched_duration);
    warn "max stitched bytes: $max_stitched_bytes (" . format_bytes($max_stitched_bytes, bs => 1000) . ")";
    #warn "Total flow count: " .  @$input_data;

    $self->_set_flow_cache( $cache );


}

sub _get_flows {
    my $self = shift;
    my $type = shift || 'all';
    my $stitched_flows = [];
    my $cache = $self->flow_cache;
    foreach my $five ( keys %$cache ) {
        my $flow_container = $cache->{$five};
        my $flows = $flow_container->{'flows'};
        #warn "flows " . Dumper $flows;
        if ( $type eq 'stitched' ) {
            push @$stitched_flows,  grep { defined $_->{'stitched'} } @$flows;
        } elsif ( $type eq 'unstitched' ) {
            push @$stitched_flows,  grep { not defined $_->{'stitched'} } @$flows;
        } else {
            # all flows
            push @$stitched_flows, @$flows;

        }
    }
    return $stitched_flows;

}

# stitches an individual flow
sub _stitch_flow {
    my ($self, $flowA, $flowB) = @_;

    my $flow1;
    my $flow2;

    # make sure flow1 comes before flow2; 
    if ( $flowA->{'start'} < $flowB->{'start'} ) {
        $flow1 = $flowA;
        $flow2 = $flowB;
    } else {
        $flow1 = $flowB;
        $flow2 = $flowA;
    }

    # TODO :extend this to other values
    $flow1->{'end'} = $flow2->{'end'};
    #warn "flow1 duration: " . $flow1->{'values'}->{'duration'} . " flow2 duration: " . $flow2->{'values'}->{'duration'} . "; sum = " . ( $flow1->{'values'}->{'duration'} + $flow2->{'values'}->{'duration'} );
    $flow1->{'values'}->{'duration'} += $flow2->{'values'}->{'duration'};
    $flow1->{'values'}->{'num_bits'} += $flow2->{'values'}->{'num_bits'};
    $flow1->{'values'}->{'num_packets'} += $flow2->{'values'}->{'num_packets'};
    $flow1->{'stitched'} = 1;

    #warn "stitched: " . Dumper $flow1;

    return $flow1;

}

# anonymizes an individual flow (TODO: remove)
sub _anonymize_flow {
    my ( $self, $ip ) = @_;
    my $cleaned;

    if ( is_ipv4($ip) ) {
        my @bytes = split(/\./, $ip);
        my $total_bytes = @bytes;
        my $num_to_remove = $self->ipv4_bits_to_strip / 8;
        my $num_to_keep = $total_bytes - $num_to_remove;
        my @new_bytes = splice @bytes, 0, $num_to_keep;
        for ( my $i=0; $i<$num_to_remove; $i++) {
            push @new_bytes, 'x';
        }
        $cleaned = join('.', @new_bytes );

    } elsif ( is_ipv6($ip) ) {
        my $ip_obj = Net::IP->new( $ip );
        my $long = $ip_obj->ip();
        #warn "$long\tlong";
        my @bytes = split(/:/, $long);
        my $total_bytes = @bytes;
        # Divide bits by 8 to get bytes; divide by 2 as there are 2 bytes per group
        my $num_to_remove = $total_bytes - $self->ipv6_bits_to_strip / 8 / 2;
        my @new_bytes = splice @bytes, 0, $num_to_remove;
        for( my $i=0; $i<$total_bytes - $num_to_remove; $i++ ) {
            push @new_bytes, 'x';
        }
        $cleaned = join(':', @new_bytes);

    } else {
        $self->logger->warn('ip address is neither ipv4 or ipv6 ' . $ip);

    }

    if ( not defined $cleaned ) {
        warn "IP was NOT CLEANED. setting blank";
        $cleaned = '';
    }

    return $cleaned;

}

sub _can_stitch_flow {
    my ($self, $time1, $time2) = @_;
    if ( abs ( $time1 - $time2 ) < $self->acceptable_offset ) {
        return 1;
    } else {
        return 0;
    }
}

1;